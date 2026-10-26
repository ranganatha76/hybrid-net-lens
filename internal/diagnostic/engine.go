package diagnostic

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"runtime"
	"slices"
	"strconv"
	"time"

	"hybrid-net-lens/internal/config"
)

type Report struct {
	SchemaVersion string        `json:"schema_version"`
	ID            string        `json:"id"`
	Vantage       string        `json:"vantage"`
	Target        config.Target `json:"target"`
	StartedAt     time.Time     `json:"started_at"`
	FinishedAt    time.Time     `json:"finished_at"`
	Status        string        `json:"status"`
	Checks        []Check       `json:"checks"`
	Findings      []Finding     `json:"findings"`
}

type Check struct {
	Phase      string            `json:"phase"`
	Address    string            `json:"address,omitempty"`
	Addresses  []string          `json:"addresses,omitempty"`
	Attempt    int               `json:"attempt,omitempty"`
	DurationMS float64           `json:"duration_ms"`
	Success    bool              `json:"success"`
	Error      string            `json:"error,omitempty"`
	HTTPStatus int               `json:"http_status,omitempty"`
	Throughput *ThroughputResult `json:"throughput,omitempty"`
	Loss       *LossResult       `json:"udp_loss,omitempty"`
	MTU        *MTUResult        `json:"mtu,omitempty"`
}

type Finding struct {
	Code           string `json:"code"`
	Severity       string `json:"severity"`
	Evidence       string `json:"evidence"`
	Recommendation string `json:"recommendation"`
}

type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type Engine struct {
	cfg             config.Config
	policy          config.Policy
	resolver        Resolver
	vantage         string
	command         commandRunner
	platform        string
	measurementSlot chan struct{}
}

// New creates a diagnostic engine only after validating its configuration.
// It builds the destination policy from the explicitly authorized CIDR list.
// The engine records the supplied vantage name for inclusion in every report.
// Defaults use Go DNS resolution, bounded subprocess execution, and the host platform.
// A single-slot channel prevents overlapping active measurement sets in this engine.
func New(cfg config.Config, vantage string) (*Engine, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	policy, err := config.NewPolicy(cfg.AllowedCIDRs)
	if err != nil {
		return nil, err
	}
	return &Engine{cfg: cfg, policy: policy, resolver: &net.Resolver{PreferGo: true}, vantage: vantage, command: runCommand, platform: runtime.GOOS, measurementSlot: make(chan struct{}, 1)}, nil
}

// Run produces a timestamped diagnostic report under a whole-run deadline.
// It resolves the target once and authorizes every answer before opening connections.
// Each authorized address receives TCP attempts and applicable TLS and HTTP checks.
// Explicitly configured active measurements run afterward if the context still permits.
// Findings determine report health, while cancellation marks the final report incomplete.
func (engine *Engine) Run(ctx context.Context, target config.Target) Report {
	ctx, cancel := context.WithTimeout(ctx, engine.cfg.RunTimeout())
	defer cancel()
	report := Report{SchemaVersion: "1", ID: newID(), Vantage: engine.vantage, Target: target, StartedAt: time.Now().UTC(), Status: "healthy", Checks: []Check{}, Findings: []Finding{}}
	addresses, check := engine.resolve(ctx, target.Host)
	report.Checks = append(report.Checks, check)
	if !check.Success {
		report.add("DNS_FAILED", "error", check.Error, "Check the configured hostname, resolver reachability, and DNS records from this vantage point.")
		return finish(report, ctx)
	}
	if len(addresses) == 0 || len(addresses) > 16 {
		report.add("ADDRESS_DENIED", "error", "Resolution must return between 1 and 16 addresses.", "Use a bounded diagnostic hostname with explicitly authorized addresses.")
		return finish(report, ctx)
	}
	for _, address := range addresses {
		if !engine.policy.Allows(address) {
			report.add("ADDRESS_DENIED", "error", fmt.Sprintf("Resolved address %s is outside policy or reserved.", address), "Verify DNS ownership and configure only the precise authorized CIDRs; metadata endpoints remain blocked.")
			return finish(report, ctx)
		}
	}
	for _, address := range addresses {
		endpoint := net.JoinHostPort(address.String(), strconv.Itoa(target.Port))
		successes := 0
		completed := 0
		for attempt := 1; attempt <= engine.cfg.Attempts && ctx.Err() == nil; attempt++ {
			check := engine.tcp(ctx, endpoint)
			check.Address, check.Attempt = address.String(), attempt
			report.Checks = append(report.Checks, check)
			completed++
			if check.Success {
				successes++
			}
		}
		if completed > 0 && successes == 0 {
			report.add("TCP_UNREACHABLE", "error", fmt.Sprintf("%s: all %d TCP connection attempts failed.", endpoint, completed), "Inspect the listener, security groups, firewall, routes, and VPN state; a failed connect does not identify which component blocked it.")
		} else if successes < completed {
			report.add("TCP_INTERMITTENT", "warning", fmt.Sprintf("%s: %d of %d TCP connection attempts failed; this is not a packet-loss measurement.", endpoint, completed-successes, completed), "Repeat from both endpoints and correlate firewall, load-balancer, and application logs.")
		}
		if ctx.Err() != nil {
			break
		}
		if successes == 0 {
			continue
		}
		if target.Protocol == "tls" || target.Protocol == "https" {
			check := engine.tls(ctx, endpoint, target.Host)
			check.Address = address.String()
			report.Checks = append(report.Checks, check)
			if !check.Success {
				report.add("TLS_FAILED", "error", fmt.Sprintf("%s: %s", endpoint, check.Error), "Check certificate validity, trust chain, hostname, TLS listener, and handshake reachability.")
				continue
			}
		}
		if (target.Protocol == "http" || target.Protocol == "https") && ctx.Err() == nil {
			check := engine.http(ctx, endpoint, target)
			check.Address = address.String()
			report.Checks = append(report.Checks, check)
			if !check.Success {
				report.add("HTTP_FAILED", "error", fmt.Sprintf("%s: %s", endpoint, check.Error), "Inspect the configured health path, expected status, reverse proxy, and application logs. Redirects are deliberately not followed.")
			}
		}
	}
	if target.Measurements != nil && ctx.Err() == nil {
		engine.measure(ctx, target, &report)
	}
	return finish(report, ctx)
}

// resolve converts a configured host into normalized, deduplicated IP addresses.
// Literal IP inputs bypass DNS and are recorded as a literal_address check.
// Hostnames use the injected resolver under the configured per-probe deadline.
// Results are unmapped, sorted, and compacted before being copied into check evidence.
// The returned check captures timing and lookup errors; authorization happens in Run.
func (engine *Engine) resolve(ctx context.Context, host string) ([]netip.Addr, Check) {
	started := time.Now()
	check := Check{Phase: "dns", Addresses: []string{}}
	var addresses []netip.Addr
	var err error
	if address, parseErr := netip.ParseAddr(host); parseErr == nil {
		check.Phase = "literal_address"
		addresses = []netip.Addr{address.Unmap()}
	} else {
		lookupCtx, cancel := context.WithTimeout(ctx, engine.cfg.Timeout())
		defer cancel()
		addresses, err = engine.resolver.LookupNetIP(lookupCtx, "ip", host)
	}
	for index := range addresses {
		addresses[index] = addresses[index].Unmap()
	}
	slices.SortFunc(addresses, func(first, second netip.Addr) int { return first.Compare(second) })
	addresses = slices.Compact(addresses)
	for _, address := range addresses {
		check.Addresses = append(check.Addresses, address.String())
	}
	check.DurationMS = elapsed(started)
	check.Success = err == nil
	if err != nil {
		check.Error = err.Error()
	}
	return addresses, check
}

// tcp attempts one TCP connection to an already selected numeric endpoint.
// It derives a per-probe deadline from the caller's run context.
// The dial tests connection establishment rather than application protocol behavior.
// Any returned connection is closed immediately to avoid retaining probe resources.
// The resulting check records elapsed milliseconds and the connection error, if any.
func (engine *Engine) tcp(ctx context.Context, endpoint string) Check {
	started := time.Now()
	probeCtx, cancel := context.WithTimeout(ctx, engine.cfg.Timeout())
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(probeCtx, "tcp", endpoint)
	if connection != nil {
		connection.Close()
	}
	return result("tcp", started, err)
}

// tls tests a verified TLS handshake against a previously authorized endpoint.
// It bounds the connection and handshake with the configured per-probe timeout.
// The configured host supplies the TLS server name and certificate identity check.
// TLS 1.2 or newer and normal certificate trust verification are required.
// It closes the connection and returns timing plus any dial or handshake error.
func (engine *Engine) tls(ctx context.Context, endpoint, host string) Check {
	started := time.Now()
	probeCtx, cancel := context.WithTimeout(ctx, engine.cfg.Timeout())
	defer cancel()
	dialer := tls.Dialer{Config: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}}
	connection, err := dialer.DialContext(probeCtx, "tcp", endpoint)
	if connection != nil {
		connection.Close()
	}
	return result("tls", started, err)
}

// http performs one bounded GET against the configured target health path.
// Its transport pins dialing to the authorized endpoint while retaining host identity.
// TLS verification, response-header limits, and context deadlines constrain the request.
// Redirects, proxy discovery, compression, and persistent connection reuse are disabled.
// It closes the response body and records failure if the status differs from expectation.
func (engine *Engine) http(ctx context.Context, endpoint string, target config.Target) Check {
	started := time.Now()
	probeCtx, cancel := context.WithTimeout(ctx, engine.cfg.Timeout())
	defer cancel()
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", endpoint)
		},
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, ServerName: target.Host},
		TLSHandshakeTimeout: engine.cfg.Timeout(), ResponseHeaderTimeout: engine.cfg.Timeout(),
		DisableKeepAlives: true, DisableCompression: true, MaxResponseHeaderBytes: 16384,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	address := url.URL{Scheme: target.Protocol, Host: net.JoinHostPort(target.Host, strconv.Itoa(target.Port)), Path: target.Path}
	request, err := http.NewRequestWithContext(probeCtx, http.MethodGet, address.String(), nil)
	if err != nil {
		return result("http", started, err)
	}
	request.Header.Set("User-Agent", "hybrid-net-lens/1")
	response, err := client.Do(request)
	check := result("http", started, err)
	if response != nil {
		response.Body.Close()
		check.HTTPStatus = response.StatusCode
		if err == nil && response.StatusCode != target.ExpectedStatus {
			check.Success = false
			check.Error = fmt.Sprintf("HTTP status %d; expected %d", response.StatusCode, target.ExpectedStatus)
		}
	}
	return check
}

// add appends one structured finding to the diagnostic report.
// The finding preserves its stable code, severity, evidence, and recommended action.
// Error severity immediately marks the report as failed.
// Other severities change a healthy report to degraded without replacing a failure.
// The method mutates only finding and status fields, leaving checks and timestamps intact.
func (report *Report) add(code, severity, evidence, recommendation string) {
	report.Findings = append(report.Findings, Finding{Code: code, Severity: severity, Evidence: evidence, Recommendation: recommendation})
	if severity == "error" {
		report.Status = "failed"
	} else if report.Status == "healthy" {
		report.Status = "degraded"
	}
}

// finish finalizes a report after its available diagnostic steps have completed.
// It checks whether the run context was canceled or exceeded its deadline.
// Interrupted runs gain a RUN_INCOMPLETE finding and an explicit incomplete status.
// Every finalized report receives a UTC completion timestamp.
// It returns the updated report value without persisting it or modifying caller context.
func finish(report Report, ctx context.Context) Report {
	if ctx.Err() != nil {
		report.add("RUN_INCOMPLETE", "error", ctx.Err().Error(), "Review completed evidence; increase the bounded run timeout or reduce targets' address count and attempts.")
		report.Status = "incomplete"
	}
	report.FinishedAt = time.Now().UTC()
	return report
}

// result constructs the common outcome fields for a single diagnostic step.
// It labels the check with the supplied phase and computes elapsed milliseconds.
// A nil error marks the check successful; any error marks it unsuccessful.
// Error text is copied into the check so the report retains failure evidence.
// Protocol-specific callers may attach addresses, statuses, or measurements afterward.
func result(phase string, started time.Time, err error) Check {
	check := Check{Phase: phase, DurationMS: elapsed(started), Success: err == nil}
	if err != nil {
		check.Error = err.Error()
	}
	return check
}

// elapsed reports time since the supplied start instant in milliseconds.
// It obtains the duration using time.Since, retaining monotonic timing when available.
// The duration is first expressed as an integer count of microseconds.
// Division by 1000 produces a fractional millisecond value for JSON check timing.
// It only computes a value and does not change any report or enforce a deadline.
func elapsed(started time.Time) float64 { return float64(time.Since(started).Microseconds()) / 1000 }

// newID creates a random identifier for a newly started diagnostic report.
// It reads 16 bytes from the operating system's cryptographic random source.
// Hex encoding produces the fixed-length lowercase identifier used in report filenames.
// Failure of the system random source panics rather than returning a weak fallback ID.
// The returned identifier contains no target, token, timestamp, or user-provided text.
func newID() string {
	identifier := make([]byte, 16)
	if _, err := rand.Read(identifier); err != nil {
		panic("system random source unavailable")
	}
	return hex.EncodeToString(identifier)
}
