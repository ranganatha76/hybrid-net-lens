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

func (run runnerFunc) Run(ctx context.Context, target config.Target) diagnostic.Report {
	return run(ctx, target)
}

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
