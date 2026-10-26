package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"hybrid-net-lens/internal/config"
	"hybrid-net-lens/internal/diagnostic"
	"hybrid-net-lens/internal/store"
)

const testToken = "test-token-at-least-thirty-two-characters"

type runnerFunc func(context.Context, config.Target) diagnostic.Report

// Run adapts a function value to the API's diagnostic Runner interface.
// It passes the supplied request context and configured target to the wrapped function.
// The function's report is returned unchanged to the service under test.
// No network execution, persistence, or validation is added by the adapter itself.
// Tests use this hook to simulate health, blocking work, and invalid report output.
func (run runnerFunc) Run(ctx context.Context, target config.Target) diagnostic.Report {
	return run(ctx, target)
}

// newService creates an isolated API service with temporary owner-only report storage.
// Configuration exposes one loopback TCP target and permits only one concurrent run.
// A supplied runner controls execution; nil selects a deterministic healthy-report fake.
// The service uses the shared test token and discards structured log output.
// Configuration or storage setup errors fail the calling test immediately.
func newService(t *testing.T, runner Runner) *Service {
	t.Helper()
	cfg := config.Config{Listen: "127.0.0.1:8080", DataDir: filepath.Join(t.TempDir(), "reports"), AllowedCIDRs: []string{"127.0.0.1/32"}, TimeoutMS: 100, RunTimeoutMS: 1000, Attempts: 1, MaxConcurrent: 1, MaxReports: 10, Targets: []config.Target{{ID: "local", Host: "localhost", Port: 80, Protocol: "tcp"}}}
	storage, err := store.New(cfg.DataDir, cfg.MaxReports)
	if err != nil {
		t.Fatal(err)
	}
	if runner == nil {
		runner = runnerFunc(func(ctx context.Context, target config.Target) diagnostic.Report {
			return diagnostic.Report{ID: "0123456789abcdef0123456789abcdef", SchemaVersion: "1", Target: target, Status: "healthy", StartedAt: time.Now()}
		})
	}
	service, err := New(cfg, runner, storage, testToken, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return service
}

// call executes an in-memory HTTP request against a service handler.
// Method, route, and string body are supplied by the calling test.
// Every request receives the JSON content type expected by run creation.
// A nonempty token becomes a Bearer authorization header; empty means unauthenticated.
// The returned recorder exposes status, headers, and response body for assertions.
func call(handler http.Handler, method, path, body, token string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

// TestAuthenticationAndHealth verifies protected routes and public probe endpoints.
// Target listing, report listing, and metrics must reject absent or incorrect tokens.
// Those same endpoints must succeed when given the configured bearer token.
// Liveness and readiness must succeed without authentication in the healthy fixture.
// The test exercises the assembled middleware stack rather than individual handlers.
func TestAuthenticationAndHealth(t *testing.T) {
	handler := newService(t, nil).Handler()
	for _, path := range []string{"/api/v1/targets", "/api/v1/runs", "/metrics"} {
		for _, token := range []string{"", "incorrect"} {
			if response := call(handler, "GET", path, "", token); response.Code != 401 {
				t.Fatalf("%s: %d", path, response.Code)
			}
		}
		if response := call(handler, "GET", path, "", testToken); response.Code != 200 {
			t.Fatalf("%s: %d", path, response.Code)
		}
	}
	for _, path := range []string{"/healthz", "/readyz"} {
		if response := call(handler, "GET", path, "", ""); response.Code != 200 {
			t.Fatalf("%s: %d", path, response.Code)
		}
	}
}

// TestRunGetListAndCooldown exercises the persisted diagnostic report workflow.
// Creating a run must return 201 and a decodable report with a retrievable identifier.
// Fetching the report and listing recent summaries must expose that same identifier.
// Metrics must record the persisted run as healthy for its configured target.
// An immediate repeat request must return 429 because the target cooldown is active.
func TestRunGetListAndCooldown(t *testing.T) {
	handler := newService(t, nil).Handler()
	response := call(handler, "POST", "/api/v1/runs", `{"target_id":"local"}`, testToken)
	if response.Code != 201 {
		t.Fatal(response.Code, response.Body.String())
	}
	var report diagnostic.Report
	if err := json.Unmarshal(response.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if response := call(handler, "GET", "/api/v1/runs/"+report.ID, "", testToken); response.Code != 200 {
		t.Fatal(response.Code)
	}
	if response := call(handler, "GET", "/api/v1/runs?limit=1", "", testToken); !strings.Contains(response.Body.String(), report.ID) {
		t.Fatal(response.Body.String())
	}
	if response := call(handler, "GET", "/metrics", "", testToken); !strings.Contains(response.Body.String(), `hybrid_net_lens_last_run_healthy{target_id="local"} 1`) {
		t.Fatal(response.Body.String())
	}
	if response := call(handler, "POST", "/api/v1/runs", `{"target_id":"local"}`, testToken); response.Code != 429 {
		t.Fatal(response.Code)
	}
}

// TestInvalidRequests verifies malformed API inputs fail with controlled responses.
// Run bodies cover missing or unknown targets, forbidden fields, extra JSON, and oversize.
// Invalid list limits and report IDs must also be rejected by their respective routes.
// A valid-looking run request without a JSON content type must receive 415.
// These cases ensure clients cannot supply arbitrary destinations through the run API.
func TestInvalidRequests(t *testing.T) {
	handler := newService(t, nil).Handler()
	for _, body := range []string{`{}`, `{"target_id":"unknown"}`, `{"target_id":"local","host":"169.254.169.254"}`, `{"target_id":"local"} {}`, strings.Repeat("x", 2048), `null`} {
		response := call(handler, "POST", "/api/v1/runs", body, testToken)
		if response.Code != 400 && response.Code != 404 {
			t.Fatalf("%s: %d", body, response.Code)
		}
	}
	if response := call(handler, "GET", "/api/v1/runs?limit=101", "", testToken); response.Code != 400 {
		t.Fatal(response.Code)
	}
	if response := call(handler, "GET", "/api/v1/runs/invalid", "", testToken); response.Code != 404 {
		t.Fatal(response.Code)
	}
	request := httptest.NewRequest("POST", "/api/v1/runs", strings.NewReader(`{"target_id":"local"}`))
	request.Header.Set("Authorization", "Bearer "+testToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != 415 {
		t.Fatal(response.Code)
	}
}

// TestConcurrencyLimit verifies admission rejects work when all run slots are occupied.
// A channel-controlled fake runner blocks the first request after it is admitted.
// A second request is issued while the configured single concurrency slot remains held.
// The blocked request is released and joined before the test finishes.
// The second response must be 429 with the busy code rather than entering the runner.
func TestConcurrencyLimit(t *testing.T) {
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	service := newService(t, runnerFunc(func(ctx context.Context, target config.Target) diagnostic.Report {
		close(entered)
		<-release
		return diagnostic.Report{ID: "0123456789abcdef0123456789abcdef", SchemaVersion: "1", Status: "healthy"}
	}))
	handler := service.Handler()
	go func() { defer close(done); call(handler, "POST", "/api/v1/runs", `{"target_id":"local"}`, testToken) }()
	<-entered
	response := call(handler, "POST", "/api/v1/runs", `{"target_id":"local"}`, testToken)
	close(release)
	<-done
	if response.Code != 429 || !strings.Contains(response.Body.String(), "busy") {
		t.Fatal(response.Code, response.Body.String())
	}
}

// TestStorageFailureIsNotSuccess verifies creation requires a persistable report.
// Its runner returns a deliberately invalid report identifier.
// The store rejects that result instead of writing an unsafe report filename.
// The API must translate the failed save into HTTP 503 rather than HTTP 201.
// The storage error counter must increase exactly once for the failed persistence attempt.
func TestStorageFailureIsNotSuccess(t *testing.T) {
	service := newService(t, runnerFunc(func(ctx context.Context, target config.Target) diagnostic.Report {
		return diagnostic.Report{ID: "invalid"}
	}))
	response := call(service.Handler(), "POST", "/api/v1/runs", `{"target_id":"local"}`, testToken)
	if response.Code != 503 {
		t.Fatal(response.Code)
	}
	if service.storageErrors.Load() != 1 {
		t.Fatal("storage failure not counted")
	}
}

// TestOlderCompletionDoesNotReplaceNewerMetric protects chronological metric updates.
// A fake runner returns a failed report with an older completion timestamp.
// The service begins with a newer healthy latest-run sample for the same target.
// Persisting the older report must still succeed and return HTTP 201.
// The newer health and timestamp must remain unchanged after that completion.
func TestOlderCompletionDoesNotReplaceNewerMetric(t *testing.T) {
	service := newService(t, runnerFunc(func(ctx context.Context, target config.Target) diagnostic.Report {
		return diagnostic.Report{ID: "0123456789abcdef0123456789abcdef", SchemaVersion: "1", Status: "failed", FinishedAt: time.Unix(100, 0)}
	}))
	service.latest["local"] = runState{finished: time.Unix(200, 0), healthy: true}
	response := call(service.Handler(), "POST", "/api/v1/runs", `{"target_id":"local"}`, testToken)
	if response.Code != 201 {
		t.Fatal(response.Code)
	}
	if !service.latest["local"].healthy || service.latest["local"].finished.Unix() != 200 {
		t.Fatal("newer metric overwritten")
	}
}
