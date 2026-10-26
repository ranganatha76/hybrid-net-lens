package diagnostic

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"hybrid-net-lens/internal/config"
)

type fakeResolver struct {
	addresses []netip.Addr
	err       error
}

// LookupNetIP supplies deterministic DNS results for engine tests.
// It implements the same lookup method used by the production resolver interface.
// Context, network, and hostname inputs do not affect this configured test double.
// The stored address slice and error are returned directly without network activity.
// Tests use it to exercise policy rejection, lookup failures, and address pinning.
func (resolver fakeResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return resolver.addresses, resolver.err
}

// testEngine creates a bounded engine and matching target for a local test server.
// It extracts the listener host and port from the HTTP or HTTPS server URL.
// The default target checks /health over HTTP and expects status 200.
// Configuration permits only IPv4 loopback and uses temporary storage and short limits.
// Setup errors fail the calling test; successful setup returns both engine and target.
func testEngine(t *testing.T, serverURL string) (*Engine, config.Target) {
	t.Helper()
	host, portValue, err := net.SplitHostPort(strings.TrimPrefix(strings.TrimPrefix(serverURL, "https://"), "http://"))
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portValue)
	target := config.Target{ID: "test", Host: host, Port: port, Protocol: "http", Path: "/health", ExpectedStatus: 200}
	cfg := config.Config{Listen: "127.0.0.1:8080", DataDir: t.TempDir(), AllowedCIDRs: []string{"127.0.0.1/32"}, TimeoutMS: 100, RunTimeoutMS: 1000, Attempts: 2, MaxConcurrent: 1, MaxReports: 10, Targets: []config.Target{target}}
	engine, err := New(cfg, "test-node")
	if err != nil {
		t.Fatal(err)
	}
	return engine, target
}

// TestHTTPHealthyAndRedirect exercises expected, redirect, and error HTTP responses.
// Each subtest runs real local TCP and HTTP probes against its own server.
// Status 200 must produce a healthy report, while 302 and 503 must fail.
// Responses advertise a separate redirect destination with a counted handler.
// The final assertion verifies that diagnostics never follow that redirect.
func TestHTTPHealthyAndRedirect(t *testing.T) {
	var redirected atomic.Int64
	destination := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) { redirected.Add(1) }))
	defer destination.Close()
	for _, status := range []int{200, 302, 503} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				writer.Header().Set("Location", destination.URL)
				writer.WriteHeader(status)
			}))
			defer server.Close()
			engine, target := testEngine(t, server.URL)
			report := engine.Run(context.Background(), target)
			if status == 200 && report.Status != "healthy" {
				t.Fatalf("%+v", report)
			}
			if status != 200 && report.Status != "failed" {
				t.Fatalf("%+v", report)
			}
		})
	}
	if redirected.Load() != 0 {
		t.Fatal("redirect followed")
	}
}

// TestPolicyChecksEveryAddressBeforeDial verifies authorization precedes all dialing.
// A fake hostname resolves to both an allowed loopback address and a metadata address.
// The reserved metadata destination must invalidate the whole resolution set.
// The report must contain only the resolution check, with no TCP probe attempted.
// An ADDRESS_DENIED finding confirms that mixed DNS answers fail closed.
func TestPolicyChecksEveryAddressBeforeDial(t *testing.T) {
	engine, target := testEngine(t, "http://127.0.0.1:12345")
	target.Host = "service.example"
	engine.resolver = fakeResolver{addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("169.254.169.254")}}
	report := engine.Run(context.Background(), target)
	if len(report.Checks) != 1 || report.Findings[0].Code != "ADDRESS_DENIED" {
		t.Fatalf("%+v", report)
	}
}

// TestDNSFailure checks how resolver errors propagate into diagnostic evidence.
// It replaces a configured hostname lookup with a deterministic failing resolver.
// Running the engine must stop before attempting any transport-level probes.
// The resulting report must have failed status instead of a healthy default.
// Its first finding must identify DNS_FAILED as the reason for the failure.
func TestDNSFailure(t *testing.T) {
	engine, target := testEngine(t, "http://127.0.0.1:12345")
	target.Host = "service.example"
	engine.resolver = fakeResolver{err: fmt.Errorf("lookup failed")}
	report := engine.Run(context.Background(), target)
	if report.Status != "failed" || report.Findings[0].Code != "DNS_FAILED" {
		t.Fatalf("%+v", report)
	}
}

// TestHTTPDialUsesResolvedAddress verifies numeric dialing preserves hostname identity.
// A local HTTP server checks the original configured hostname in the Host header.
// The target hostname is deliberately unresolvable by normal external DNS.
// An injected resolver maps it to the authorized loopback server address.
// A healthy report proves the HTTP transport uses the pinned address successfully.
func TestHTTPDialUsesResolvedAddress(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !strings.HasPrefix(request.Host, "unresolvable.invalid:") {
			t.Errorf("unexpected Host %s", request.Host)
		}
	}))
	defer server.Close()
	engine, target := testEngine(t, server.URL)
	target.Host = "unresolvable.invalid"
	engine.resolver = fakeResolver{addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	report := engine.Run(context.Background(), target)
	if report.Status != "healthy" {
		t.Fatalf("%+v", report)
	}
}

// TestTLSRejectsUntrustedCertificate exercises normal certificate trust enforcement.
// It starts a local HTTPS server using the test server's untrusted certificate.
// The diagnostic target is changed to HTTPS while retaining the local endpoint.
// Running diagnostics must fail rather than bypassing certificate verification.
// The report must identify TLS_FAILED before an HTTP health check can succeed.
func TestTLSRejectsUntrustedCertificate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	engine, target := testEngine(t, server.URL)
	target.Protocol = "https"
	report := engine.Run(context.Background(), target)
	if report.Status != "failed" || report.Findings[0].Code != "TLS_FAILED" {
		t.Fatalf("%+v", report)
	}
}

// TestDeadlineAndCancellation verifies probes stop when their context budget expires.
// A local handler waits until the request context is canceled instead of replying.
// The ordinary run must fail within the asserted one-second upper bound.
// A second run receives a context that has already been explicitly canceled.
// That run must report incomplete status rather than misrepresenting partial evidence.
func TestDeadlineAndCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) { <-request.Context().Done() }))
	defer server.Close()
	engine, target := testEngine(t, server.URL)
	started := time.Now()
	report := engine.Run(context.Background(), target)
	if report.Status != "failed" || time.Since(started) > time.Second {
		t.Fatalf("%+v", report)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if report := engine.Run(ctx, target); report.Status != "incomplete" {
		t.Fatalf("%+v", report)
	}
}

// TestTCPUnreachable checks reporting when no listener accepts the target connection.
// It builds an engine from a local server address and then closes that server.
// All configured TCP attempts therefore target the now-unavailable endpoint.
// The report must fail and contain exactly one aggregated reachability finding.
// That finding must use TCP_UNREACHABLE rather than a TLS or HTTP failure code.
func TestTCPUnreachable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	engine, target := testEngine(t, server.URL)
	server.Close()
	report := engine.Run(context.Background(), target)
	if report.Status != "failed" || len(report.Findings) != 1 || report.Findings[0].Code != "TCP_UNREACHABLE" {
		t.Fatalf("%+v", report)
	}
}
