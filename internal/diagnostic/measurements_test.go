package diagnostic

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"hybrid-net-lens/internal/config"
)

// TestIPerfJSONAndBudget exercises argument safety and receiver statistic decoding.
// Its command double verifies the executable, literal destination, and configured rate.
// A fixed receiver summary must produce the expected TCP Mbps and UDP loss percentage.
// Invalid, empty, trailing, or error-bearing output must never yield a successful check.
// All measurements run through the fake command runner without generating network traffic.
func TestIPerfJSONAndBudget(t *testing.T) {
	engine, _ := testEngine(t, "http://127.0.0.1:12345")
	measurement := config.Measurements{Throughput: true, UDPLoss: true, IPerfPort: 5201, DurationSeconds: 1, RateMbps: 5}
	engine.command = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		if name != "iperf3" || !strings.Contains(joined, "--client 127.0.0.1") || !strings.Contains(joined, "--bitrate 5M") {
			t.Fatalf("unsafe command: %s %s", name, joined)
		}
		return []byte(`{"end":{"sum_received":{"bytes":100000,"seconds":1,"bits_per_second":800000,"packets":100,"lost_packets":2,"jitter_ms":0.2}}}`), nil
	}
	if result := engine.iperf(context.Background(), "127.0.0.1", measurement, false); !result.Success || result.Throughput.Mbps != 0.8 {
		t.Fatalf("%+v", result)
	}
	if result := engine.iperf(context.Background(), "127.0.0.1", measurement, true); !result.Success || result.Loss.LossPercent != 2 {
		t.Fatalf("%+v", result)
	}
	for _, data := range []string{`{}`, `{"error":"busy"}`, `{"end":{"sum_received":{"seconds":1,"packets":0}}}`, `{} {}`, `invalid`} {
		engine.command = func(context.Context, string, ...string) ([]byte, error) { return []byte(data), nil }
		if result := engine.iperf(context.Background(), "127.0.0.1", measurement, true); result.Success {
			t.Fatalf("accepted %s", data)
		}
	}
}

// TestMTUBoundaryAndTimeout simulates a Linux path with a 1400-byte packet boundary.
// The command double accepts smaller packets and returns explicit too-big evidence above it.
// Search results must confirm 1400, reject 1401, and stay within the probe-count budget.
// Replacing replies with generic failures must produce no successful MTU estimate.
// Switching the engine platform to Darwin must reject Linux-specific probing outright.
func TestMTUBoundaryAndTimeout(t *testing.T) {
	engine, _ := testEngine(t, "http://127.0.0.1:12345")
	engine.platform = "linux"
	measurement := config.Measurements{MTU: true, MTUMin: 1280, MTUMax: 1600}
	engine.command = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		payload := 0
		for index, arg := range args {
			if arg == "-s" {
				payload, _ = strconv.Atoi(args[index+1])
			}
		}
		if payload+28 > 1400 {
			return []byte("message too long, mtu=1400"), errors.New("exit 1")
		}
		return nil, nil
	}
	result := engine.mtu(context.Background(), "127.0.0.1", measurement)
	if !result.Success || result.MTU.LargestConfirmedBytes != 1400 || result.MTU.SmallestRejectedBytes != 1401 || result.MTU.Probes > 12 {
		t.Fatalf("%+v %+v", result, result.MTU)
	}
	engine.command = func(context.Context, string, ...string) ([]byte, error) { return nil, fmt.Errorf("no reply") }
	if result := engine.mtu(context.Background(), "127.0.0.1", measurement); result.Success || result.MTU.LargestConfirmedBytes != 0 {
		t.Fatalf("%+v", result)
	}
	engine.platform = "darwin"
	if result := engine.mtu(context.Background(), "127.0.0.1", measurement); result.Success || !strings.Contains(result.Error, "Linux") {
		t.Fatalf("%+v", result)
	}
}

// TestMTULowerBound checks interpretation when every configured packet size succeeds.
// It uses a Linux engine with a command double that accepts every ping probe.
// The search interval spans 1280 through 1500 bytes.
// The largest confirmed result must reach the configured 1500-byte ceiling.
// Confidence must remain lower_bound because no larger packet was explicitly rejected.
func TestMTULowerBound(t *testing.T) {
	engine, _ := testEngine(t, "http://127.0.0.1:12345")
	engine.platform = "linux"
	engine.command = func(context.Context, string, ...string) ([]byte, error) { return nil, nil }
	result := engine.mtu(context.Background(), "127.0.0.1", config.Measurements{MTU: true, MTUMin: 1280, MTUMax: 1500})
	if !result.Success || result.MTU.Confidence != "lower_bound" || result.MTU.LargestConfirmedBytes != 1500 {
		t.Fatalf("%+v", result)
	}
}

// TestBoundedCommandOutput verifies enforcement of the subprocess buffer budget.
// It constructs a capture buffer with a deliberately small four-byte maximum.
// A single five-byte write attempts to exceed that budget.
// The writer must return an error instead of accepting the oversized data.
// Its exceeded flag must also be set for the command runner's final overflow check.
func TestBoundedCommandOutput(t *testing.T) {
	output := &boundedOutput{maximum: 4}
	if _, err := output.Write([]byte("12345")); err == nil || !output.exceeded {
		t.Fatal("unbounded output accepted")
	}
}

// TestMissingDependency checks that active measurements fail preflight without tools.
// It replaces PATH with an empty temporary directory for the duration of the test.
// A throughput-enabled configuration must fail because iperf3 cannot be discovered.
// An empty baseline-only configuration must not require that executable.
// Environment isolation avoids depending on tools installed on the developer machine.
func TestMissingDependency(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	cfg := config.Config{Targets: []config.Target{{Measurements: &config.Measurements{Throughput: true}}}}
	if err := CheckDependencies(cfg); err == nil {
		t.Fatal("accepted unavailable iperf3")
	}
	if err := CheckDependencies(config.Config{}); err != nil {
		t.Fatal(err)
	}
}

// TestNormalizedMeasurementPeer verifies normalization before an active command is built.
// The configured peer uses the IPv4-mapped IPv6 representation of loopback.
// A command double requires the actual iperf argument to be plain IPv4 loopback.
// It returns a valid receiver summary so the throughput measurement can complete.
// The report must contain one successful measurement check using that normalized peer.
func TestNormalizedMeasurementPeer(t *testing.T) {
	engine, target := testEngine(t, "http://127.0.0.1:12345")
	target.Host = "::ffff:127.0.0.1"
	target.Measurements = &config.Measurements{Throughput: true, IPerfPort: 5201, DurationSeconds: 1, RateMbps: 1}
	engine.command = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if args[1] != "127.0.0.1" {
			t.Fatalf("un-normalized peer: %v", args)
		}
		return []byte(`{"end":{"sum_received":{"bytes":125000,"seconds":1,"bits_per_second":1000000}}}`), nil
	}
	report := Report{Status: "healthy"}
	engine.measure(context.Background(), target, &report)
	if len(report.Checks) != 1 || !report.Checks[0].Success {
		t.Fatalf("%+v", report)
	}
}
