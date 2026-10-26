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

func (resolver fakeResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return resolver.addresses, resolver.err
}

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

func TestPolicyChecksEveryAddressBeforeDial(t *testing.T) {
	engine, target := testEngine(t, "http://127.0.0.1:12345")
	target.Host = "service.example"
	engine.resolver = fakeResolver{addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("169.254.169.254")}}
	report := engine.Run(context.Background(), target)
	if len(report.Checks) != 1 || report.Findings[0].Code != "ADDRESS_DENIED" {
		t.Fatalf("%+v", report)
	}
}

func TestDNSFailure(t *testing.T) {
	engine, target := testEngine(t, "http://127.0.0.1:12345")
	target.Host = "service.example"
	engine.resolver = fakeResolver{err: fmt.Errorf("lookup failed")}
	report := engine.Run(context.Background(), target)
	if report.Status != "failed" || report.Findings[0].Code != "DNS_FAILED" {
		t.Fatalf("%+v", report)
	}
}

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

func TestTCPUnreachable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	engine, target := testEngine(t, server.URL)
	server.Close()
	report := engine.Run(context.Background(), target)
	if report.Status != "failed" || len(report.Findings) != 1 || report.Findings[0].Code != "TCP_UNREACHABLE" {
		t.Fatalf("%+v", report)
	}
}
