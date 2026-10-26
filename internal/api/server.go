package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"hybrid-net-lens/internal/config"
	"hybrid-net-lens/internal/diagnostic"
	"hybrid-net-lens/internal/store"
)

type Runner interface {
	Run(context.Context, config.Target) diagnostic.Report
}

type Service struct {
	cfg           config.Config
	runner        Runner
	storage       *store.Store
	logger        *slog.Logger
	tokenHash     [32]byte
	slots         chan struct{}
	mu            sync.Mutex
	lastRun       map[string]time.Time
	latest        map[string]runState
	requests      atomic.Uint64
	runs          atomic.Uint64
	storageErrors atomic.Uint64
}

type runState struct {
	finished time.Time
	healthy  bool
}

// New builds an API service from validated configuration and required dependencies.
// It requires a 32..512-character printable ASCII bearer token without whitespace.
// Runner, report storage, and structured logger must all be supplied by the caller.
// Only the token's SHA-256 hash is retained for subsequent authentication checks.
// Admission slots, per-target cooldowns, and latest-result state start empty.
func New(cfg config.Config, runner Runner, storage *store.Store, token string, logger *slog.Logger) (*Service, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if len(token) < 32 || len(token) > 512 || strings.IndexFunc(token, func(character rune) bool { return character < 33 || character > 126 }) != -1 {
		return nil, errors.New("API token must be 32..512 printable ASCII characters without whitespace")
	}
	if runner == nil || storage == nil || logger == nil {
		return nil, errors.New("runner, storage, and logger are required")
	}
	return &Service{cfg: cfg, runner: runner, storage: storage, logger: logger, tokenHash: sha256.Sum256([]byte(token)), slots: make(chan struct{}, cfg.MaxConcurrent), lastRun: make(map[string]time.Time), latest: make(map[string]runState)}, nil
}

// Handler assembles public health endpoints and authenticated diagnostic API routes.
// Readiness checks storage, while targets, reports, runs, and metrics require a token.
// An outer wrapper adds request IDs, no-cache headers, and content-type protection.
// Requests are counted and logged by matched route without logging authorization values.
// Panic recovery logs the event and emits a JSON error if no response was started.
func (service *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(writer http.ResponseWriter, request *http.Request) {
		writeJSON(writer, http.StatusOK, map[string]string{"status": "alive"})
	})
	mux.HandleFunc("GET /readyz", func(writer http.ResponseWriter, request *http.Request) {
		if err := service.storage.Ready(); err != nil {
			writeError(writer, http.StatusServiceUnavailable, "not_ready", "Report storage is unavailable.")
			return
		}
		writeJSON(writer, http.StatusOK, map[string]string{"status": "ready"})
	})
	mux.Handle("GET /metrics", service.authorize(http.HandlerFunc(service.metrics)))
	mux.Handle("GET /api/v1/targets", service.authorize(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writeJSON(writer, http.StatusOK, map[string]any{"targets": service.cfg.Targets})
	})))
	mux.Handle("POST /api/v1/runs", service.authorize(http.HandlerFunc(service.run)))
	mux.Handle("GET /api/v1/runs", service.authorize(http.HandlerFunc(service.list)))
	mux.Handle("GET /api/v1/runs/{id}", service.authorize(http.HandlerFunc(service.get)))
	mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		writeError(writer, http.StatusNotFound, "not_found", "Endpoint not found.")
	})
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		started := time.Now()
		requestID := rand.Text()
		writer.Header().Set("X-Request-ID", requestID)
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		tracked := &responseWriter{ResponseWriter: writer, status: http.StatusOK}
		service.requests.Add(1)
		defer func() {
			if recovered := recover(); recovered != nil {
				service.logger.Error("request panic", "request_id", requestID)
				if !tracked.wrote {
					writeError(tracked, http.StatusInternalServerError, "internal_error", "Internal server error.")
				}
			}
			service.logger.Info("request", "request_id", requestID, "method", request.Method, "route", request.Pattern, "status", tracked.status, "duration_ms", time.Since(started).Milliseconds())
		}()
		mux.ServeHTTP(tracked, request)
	})
}

// authorize wraps a handler with mandatory bearer-token authentication.
// It extracts the Authorization header and requires the exact Bearer prefix.
// The provided token is hashed before constant-time comparison with the stored hash.
// Invalid credentials receive a JSON 401 response and a WWW-Authenticate challenge.
// Only authenticated requests reach the wrapped handler; token values are not logged here.
func (service *Service) authorize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		value := request.Header.Get("Authorization")
		provided := strings.TrimPrefix(value, "Bearer ")
		hash := sha256.Sum256([]byte(provided))
		if !strings.HasPrefix(value, "Bearer ") || subtle.ConstantTimeCompare(hash[:], service.tokenHash[:]) != 1 {
			writer.Header().Set("WWW-Authenticate", `Bearer realm="hybrid-net-lens"`)
			writeError(writer, http.StatusUnauthorized, "unauthorized", "A valid bearer token is required.")
			return
		}
		next.ServeHTTP(writer, request)
	})
}

// run accepts one bounded JSON request naming an already configured diagnostic target.
// It rejects unknown fields, extra JSON, unsupported media types, and unknown target IDs.
// Nonblocking concurrency admission and a five-second target cooldown limit workload.
// The request context bounds execution, and storage must save the completed report.
// Only persisted reports receive 201 and a Location header, regardless of diagnostic health.
func (service *Service) run(writer http.ResponseWriter, request *http.Request) {
	if strings.Split(request.Header.Get("Content-Type"), ";")[0] != "application/json" {
		writeError(writer, http.StatusUnsupportedMediaType, "content_type", "Use application/json.")
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, 1024)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var input struct {
		TargetID string `json:"target_id"`
	}
	if err := decoder.Decode(&input); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", "Expected a JSON object with target_id only (maximum 1024 bytes).")
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		writeError(writer, http.StatusBadRequest, "invalid_request", "Expected exactly one JSON object.")
		return
	}
	var target config.Target
	for _, candidate := range service.cfg.Targets {
		if candidate.ID == input.TargetID {
			target = candidate
			break
		}
	}
	if target.ID == "" {
		writeError(writer, http.StatusNotFound, "target_not_found", "Configured target not found.")
		return
	}
	select {
	case service.slots <- struct{}{}:
		defer func() { <-service.slots }()
	default:
		writer.Header().Set("Retry-After", "5")
		writeError(writer, http.StatusTooManyRequests, "busy", "Diagnostic concurrency limit reached.")
		return
	}
	service.mu.Lock()
	now := time.Now()
	last := service.lastRun[target.ID]
	if now.Sub(last) < 5*time.Second {
		service.mu.Unlock()
		writer.Header().Set("Retry-After", "5")
		writeError(writer, http.StatusTooManyRequests, "cooldown", "Wait at least five seconds between runs of this target.")
		return
	}
	service.lastRun[target.ID] = now
	service.mu.Unlock()
	service.runs.Add(1)
	report := service.runner.Run(request.Context(), target)
	if err := service.storage.Save(report); err != nil {
		service.storageErrors.Add(1)
		service.logger.Error("persist report", "report_id", report.ID, "error", err)
		writeError(writer, http.StatusServiceUnavailable, "storage_unavailable", "Could not durably save the report; retry later.")
		return
	}
	service.mu.Lock()
	if previous, exists := service.latest[target.ID]; !exists || !report.FinishedAt.Before(previous.finished) {
		service.latest[target.ID] = runState{finished: report.FinishedAt, healthy: report.Status == "healthy"}
	}
	service.mu.Unlock()
	service.logger.Info("diagnostic completed", "report_id", report.ID, "target_id", target.ID, "status", report.Status)
	writer.Header().Set("Location", "/api/v1/runs/"+report.ID)
	writeJSON(writer, http.StatusCreated, report)
}

// get returns one persisted report selected by the route's report ID.
// Identifier validation and bounded report reading are delegated to the store.
// Missing, invalid, or retention-expired identifiers map to a JSON 404 response.
// Other storage failures return 503 rather than exposing an unreadable report.
// Successfully loaded reports are serialized with HTTP 200 in the standard JSON format.
func (service *Service) get(writer http.ResponseWriter, request *http.Request) {
	report, err := service.storage.Get(request.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(writer, http.StatusNotFound, "report_not_found", "Report not found or expired by retention.")
		return
	}
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "storage_unavailable", "Could not read the report.")
		return
	}
	writeJSON(writer, http.StatusOK, report)
}

// list returns recent persisted report summaries in a JSON reports envelope.
// The default result limit is 20 unless the request supplies a limit query value.
// Explicit limits must parse as integers between one and 100 inclusive.
// Storage selects and orders the summaries; failures produce a JSON 503 response.
// Invalid limits return 400 before the store is queried.
func (service *Service) list(writer http.ResponseWriter, request *http.Request) {
	limit := 20
	if value := request.URL.Query().Get("limit"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 100 {
			writeError(writer, http.StatusBadRequest, "invalid_limit", "limit must be 1..100.")
			return
		}
		limit = parsed
	}
	reports, err := service.storage.List(limit)
	if err != nil {
		writeError(writer, http.StatusServiceUnavailable, "storage_unavailable", "Could not list reports.")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"reports": reports})
}

// metrics writes the service's Prometheus text-format counters and gauges.
// Atomic counters expose requests, started runs, and failed report saves.
// Current admission-slot occupancy supplies the active diagnostic request gauge.
// A mutex protects per-target latest persisted health and completion timestamps.
// Targets without a persisted result in this process do not emit latest-run samples.
func (service *Service) metrics(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	fmt.Fprintf(writer, "# HELP hybrid_net_lens_requests_total HTTP requests received.\n# TYPE hybrid_net_lens_requests_total counter\nhybrid_net_lens_requests_total %d\n# HELP hybrid_net_lens_runs_total Diagnostic runs started.\n# TYPE hybrid_net_lens_runs_total counter\nhybrid_net_lens_runs_total %d\n# HELP hybrid_net_lens_active_runs Currently active diagnostic requests.\n# TYPE hybrid_net_lens_active_runs gauge\nhybrid_net_lens_active_runs %d\n# HELP hybrid_net_lens_storage_errors_total Failed report saves.\n# TYPE hybrid_net_lens_storage_errors_total counter\nhybrid_net_lens_storage_errors_total %d\n", service.requests.Load(), service.runs.Load(), len(service.slots), service.storageErrors.Load())
	fmt.Fprint(writer, "# HELP hybrid_net_lens_last_run_healthy Whether the latest persisted run was healthy.\n# TYPE hybrid_net_lens_last_run_healthy gauge\n# HELP hybrid_net_lens_last_run_timestamp_seconds Latest persisted run completion time.\n# TYPE hybrid_net_lens_last_run_timestamp_seconds gauge\n")
	service.mu.Lock()
	defer service.mu.Unlock()
	for _, target := range service.cfg.Targets {
		if state, exists := service.latest[target.ID]; exists {
			healthy := 0
			if state.healthy {
				healthy = 1
			}
			fmt.Fprintf(writer, "hybrid_net_lens_last_run_healthy{target_id=%q} %d\nhybrid_net_lens_last_run_timestamp_seconds{target_id=%q} %d\n", target.ID, healthy, target.ID, state.finished.Unix())
		}
	}
}

type responseWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

// WriteHeader tracks the first status sent through the response wrapper.
// Repeated header writes are ignored once a response has already started.
// The chosen status is retained for request logging and panic recovery decisions.
// The wrote flag records that an explicit or implicit response has begun.
// The first status is forwarded unchanged to the underlying HTTP response writer.
func (writer *responseWriter) WriteHeader(status int) {
	if writer.wrote {
		return
	}
	writer.status, writer.wrote = status, true
	writer.ResponseWriter.WriteHeader(status)
}

// Write sends response body bytes while keeping status tracking consistent.
// If headers have not been written, it first records and sends HTTP 200.
// Existing response statuses are preserved when writing additional body data.
// Payload bytes are delegated unchanged to the underlying HTTP response writer.
// The method returns that writer's byte count and error without additional buffering.
func (writer *responseWriter) Write(data []byte) (int, error) {
	if !writer.wrote {
		writer.WriteHeader(http.StatusOK)
	}
	return writer.ResponseWriter.Write(data)
}

// writeJSON emits a value using the API's JSON response content type.
// It sets UTF-8 JSON headers before sending the supplied HTTP status.
// The standard encoder serializes the value directly to the response stream.
// Encoding appends a newline and does not buffer or retry an already started response.
// Callers supply JSON-compatible values; this helper does not return encoding errors.
func writeJSON(writer http.ResponseWriter, status int, data any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(status)
	json.NewEncoder(writer).Encode(data)
}

// writeError emits the API's consistent nested JSON error envelope.
// It pairs a machine-readable error code with a caller-provided human message.
// The caller selects the HTTP status appropriate to the rejected operation.
// Serialization and JSON content-type handling are delegated to writeJSON.
// It sends no raw error objects, stack traces, or additional diagnostic report fields.
func writeError(writer http.ResponseWriter, status int, code, message string) {
	writeJSON(writer, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}
