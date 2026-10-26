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

func (report *Report) add(code, severity, evidence, recommendation string) {
	report.Findings = append(report.Findings, Finding{Code: code, Severity: severity, Evidence: evidence, Recommendation: recommendation})
	if severity == "error" {
		report.Status = "failed"
	} else if report.Status == "healthy" {
		report.Status = "degraded"
	}
}

func finish(report Report, ctx context.Context) Report {
	if ctx.Err() != nil {
		report.add("RUN_INCOMPLETE", "error", ctx.Err().Error(), "Review completed evidence; increase the bounded run timeout or reduce targets' address count and attempts.")
		report.Status = "incomplete"
	}
	report.FinishedAt = time.Now().UTC()
	return report
}

func result(phase string, started time.Time, err error) Check {
	check := Check{Phase: phase, DurationMS: elapsed(started), Success: err == nil}
	if err != nil {
		check.Error = err.Error()
	}
	return check
}

func elapsed(started time.Time) float64 { return float64(time.Since(started).Microseconds()) / 1000 }

func newID() string {
	identifier := make([]byte, 16)
	if _, err := rand.Read(identifier); err != nil {
		panic("system random source unavailable")
	}
	return hex.EncodeToString(identifier)
}
