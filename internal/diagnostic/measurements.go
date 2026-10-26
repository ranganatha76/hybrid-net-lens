package diagnostic

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"hybrid-net-lens/internal/config"
)

type ThroughputResult struct {
	Direction     string  `json:"direction"`
	Mbps          float64 `json:"mbps"`
	Bytes         int64   `json:"bytes"`
	Seconds       float64 `json:"seconds"`
	RateLimitMbps int     `json:"rate_limit_mbps"`
}

type LossResult struct {
	Packets      int64   `json:"packets"`
	LostPackets  int64   `json:"lost_packets"`
	LossPercent  float64 `json:"loss_percent"`
	JitterMS     float64 `json:"jitter_ms"`
	OfferedMbps  int     `json:"offered_mbps"`
	PayloadBytes int     `json:"payload_bytes"`
}

type MTUResult struct {
	LargestConfirmedBytes int    `json:"largest_confirmed_bytes"`
	SmallestRejectedBytes int    `json:"smallest_rejected_bytes,omitempty"`
	SearchCeilingBytes    int    `json:"search_ceiling_bytes"`
	Probes                int    `json:"probes"`
	Confidence            string `json:"confidence"`
}

type commandRunner func(context.Context, string, ...string) ([]byte, error)

type boundedOutput struct {
	data     bytes.Buffer
	maximum  int
	exceeded bool
}

// Write appends subprocess output only while the configured byte limit permits.
// It checks the current buffer length plus the entire incoming write before appending.
// An oversized write sets the exceeded flag and returns an error without partial storage.
// Successful writes delegate to the underlying buffer and report its byte count.
// The command runner inspects the flag to reject probes that exceed output budgets.
func (output *boundedOutput) Write(data []byte) (int, error) {
	if output.data.Len()+len(data) > output.maximum {
		output.exceeded = true
		return 0, errors.New("probe output exceeded limit")
	}
	return output.data.Write(data)
}

// runCommand executes a probe directly with arguments and context cancellation.
// The child receives only PATH and fixed locale settings, excluding API token variables.
// Captured stdout is limited to 1 MiB and stderr to 16 KiB, with bounded wait delay.
// Output overflow and context cancellation take precedence over ordinary exit errors.
// Failed ping probes include stderr so MTU logic can recognize packet-too-big evidence.
func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.WaitDelay = time.Second
	command.Env = []string{"PATH=" + os.Getenv("PATH"), "LC_ALL=C", "LANG=C"}
	stdout := &boundedOutput{maximum: 1 << 20}
	stderr := &boundedOutput{maximum: 16384}
	command.Stdout, command.Stderr = stdout, stderr
	err := command.Run()
	if stdout.exceeded || stderr.exceeded {
		return nil, errors.New("probe output exceeded limit")
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil && name == "ping" {
		return append(stdout.data.Bytes(), stderr.data.Bytes()...), err
	}
	return stdout.data.Bytes(), err
}

// CheckDependencies verifies tools required by explicitly enabled active tests.
// Throughput or UDP loss measurements require an iperf3 executable on PATH.
// MTU measurements require Linux and a discoverable ping executable.
// Required executable names are deduplicated across all configured targets.
// Baseline-only configurations need no external tools and pass without these binaries.
func CheckDependencies(cfg config.Config) error {
	required := map[string]bool{}
	for _, target := range cfg.Targets {
		if target.Measurements == nil {
			continue
		}
		if target.Measurements.Throughput || target.Measurements.UDPLoss {
			required["iperf3"] = true
		}
		if target.Measurements.MTU {
			if runtime.GOOS != "linux" {
				return errors.New("enabled MTU measurements require Linux iputils ping")
			}
			required["ping"] = true
		}
	}
	for name := range required {
		if _, err := exec.LookPath(name); err != nil {
			return fmt.Errorf("enabled measurements require %s: %w", name, err)
		}
	}
	return nil
}

// measure appends explicitly requested active-test evidence to an existing report.
// It normalizes the validated literal peer and attempts the engine's single test slot.
// Contention records MEASUREMENT_BUSY immediately instead of queueing more traffic.
// Enabled throughput, UDP loss, and MTU tests run sequentially while context allows.
// Failures and observed UDP loss add findings; deferred release always frees the slot.
func (engine *Engine) measure(ctx context.Context, target config.Target, report *Report) {
	target.Host = netip.MustParseAddr(target.Host).Unmap().String()
	select {
	case engine.measurementSlot <- struct{}{}:
		defer func() { <-engine.measurementSlot }()
	default:
		report.add("MEASUREMENT_BUSY", "error", "Another active measurement is running in this process.", "Retry later; active bandwidth tests are serialized to avoid self-interference.")
		return
	}
	measurement := *target.Measurements
	for _, udp := range []bool{false, true} {
		if (!udp && !measurement.Throughput) || (udp && !measurement.UDPLoss) || ctx.Err() != nil {
			continue
		}
		check := engine.iperf(ctx, target.Host, measurement, udp)
		report.Checks = append(report.Checks, check)
		if !check.Success {
			report.add("MEASUREMENT_FAILED", "error", check.Phase+": "+check.Error, "Check the installed iperf3 version, peer listener, firewall, traffic budget, and deadlines; do not interpret a failed benchmark as zero throughput.")
		}
		if check.Loss != nil && check.Loss.LostPackets > 0 {
			report.add("UDP_DELIVERY_LOSS", "warning", fmt.Sprintf("%d of %d UDP datagrams lost at %d Mbps (%.3f%%).", check.Loss.LostPackets, check.Loss.Packets, measurement.RateMbps, check.Loss.LossPercent), "Compare a lower offered rate and inspect receiver/host counters; delivery loss may include host overload or queue drops, not only the network.")
		}
	}
	if measurement.MTU && ctx.Err() == nil {
		check := engine.mtu(ctx, target.Host, measurement)
		report.Checks = append(report.Checks, check)
		if !check.Success {
			report.add("MTU_INCONCLUSIVE", "error", check.Error, "Allow ICMP echo and packet-too-big messages, verify ping datagram socket permissions, and repeat from the same namespace. No reply is not proof of an MTU boundary.")
		}
	}
}

type iperfSummary struct {
	Bytes         int64   `json:"bytes"`
	Seconds       float64 `json:"seconds"`
	BitsPerSecond float64 `json:"bits_per_second"`
	Packets       int64   `json:"packets"`
	LostPackets   int64   `json:"lost_packets"`
	JitterMS      float64 `json:"jitter_ms"`
	Sender        bool    `json:"sender"`
}

type iperfOutput struct {
	Error string `json:"error"`
	End   struct {
		Received *iperfSummary `json:"sum_received"`
		Sum      *iperfSummary `json:"sum"`
	} `json:"end"`
}

// iperf runs a rate-capped upload measurement against the configured literal peer.
// TCP mode reports receiver goodput; UDP mode uses fixed 1200-byte payloads.
// Arguments include the approved port, duration, bitrate, and connection timeout.
// Output must be one JSON value with a valid receiver summary and finite statistics.
// The returned check contains either throughput or loss evidence, or a specific error.
func (engine *Engine) iperf(ctx context.Context, host string, measurement config.Measurements, udp bool) Check {
	started := time.Now()
	phase := "throughput"
	args := []string{"--client", host, "--port", strconv.Itoa(measurement.IPerfPort), "--json", "--time", strconv.Itoa(measurement.DurationSeconds), "--bitrate", strconv.Itoa(measurement.RateMbps) + "M", "--connect-timeout", strconv.Itoa(engine.cfg.TimeoutMS)}
	if udp {
		phase = "udp_loss"
		args = append(args, "--udp", "--length", "1200", "--get-server-output")
	}
	probeCtx, cancel := context.WithTimeout(ctx, time.Duration(measurement.DurationSeconds)*time.Second+engine.cfg.Timeout()+3*time.Second)
	defer cancel()
	data, runErr := engine.command(probeCtx, "iperf3", args...)
	check := Check{Phase: phase, Address: host, DurationMS: elapsed(started)}
	var output iperfOutput
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&output); err != nil {
		check.Error = "iperf3 did not return valid JSON"
		if runErr != nil {
			check.Error = runErr.Error()
		}
		return check
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		check.Error = "iperf3 returned trailing data"
		return check
	}
	if output.Error != "" {
		check.Error = output.Error
		return check
	}
	if runErr != nil {
		check.Error = runErr.Error()
		return check
	}
	summary := output.End.Received
	if summary == nil && udp {
		summary = output.End.Sum
	}
	if summary == nil || summary.Bytes < 0 || summary.Seconds <= 0 || !finite(summary.Seconds) || summary.BitsPerSecond < 0 || !finite(summary.BitsPerSecond) {
		check.Error = "iperf3 receiver summary is missing or invalid"
		return check
	}
	if udp {
		if summary.Packets <= 0 || summary.LostPackets < 0 || summary.LostPackets > summary.Packets || summary.JitterMS < 0 || !finite(summary.JitterMS) {
			check.Error = "iperf3 UDP delivery statistics are missing or invalid"
			return check
		}
		check.Loss = &LossResult{Packets: summary.Packets, LostPackets: summary.LostPackets, LossPercent: float64(summary.LostPackets) * 100 / float64(summary.Packets), JitterMS: summary.JitterMS, OfferedMbps: measurement.RateMbps, PayloadBytes: 1200}
	} else {
		check.Throughput = &ThroughputResult{Direction: "upload", Mbps: summary.BitsPerSecond / 1e6, Bytes: summary.Bytes, Seconds: summary.Seconds, RateLimitMbps: measurement.RateMbps}
	}
	check.Success = true
	return check
}

// finite determines whether a floating-point measurement is numerically finite.
// It rejects NaN values, which cannot support meaningful measurement comparisons.
// It also rejects positive and negative infinity from probe statistics.
// Zero and finite negative values pass this helper and need field-specific validation.
// The result supports validation of duration, bitrate, and jitter before reporting them.
func finite(value float64) bool { return !math.IsNaN(value) && !math.IsInf(value, 0) }

// mtu searches a configured packet-size interval using Linux DF ICMP echo probes.
// It selects IPv4 or IPv6 payload overhead and requires the minimum size to reply.
// A binary search advances confirmed sizes or narrows on explicit packet-too-big errors.
// Missing replies and command timeouts remain inconclusive rather than implying an MTU.
// The check reports probe count and either a bounded estimate or a confirmed lower bound.
func (engine *Engine) mtu(ctx context.Context, host string, measurement config.Measurements) Check {
	started := time.Now()
	check := Check{Phase: "mtu", Address: host, MTU: &MTUResult{SearchCeilingBytes: measurement.MTUMax, Confidence: "inconclusive"}}
	if engine.platform != "linux" {
		check.Error = "MTU probes require Linux iputils ping; this platform is " + engine.platform
		return check
	}
	address := netip.MustParseAddr(host)
	overhead, family := 28, "-4"
	if address.Is6() {
		overhead, family = 48, "-6"
	}
	probe := func(size int) (bool, bool, error) {
		probeCtx, cancel := context.WithTimeout(ctx, engine.cfg.Timeout())
		defer cancel()
		check.MTU.Probes++
		data, err := engine.command(probeCtx, "ping", family, "-n", "-c", "1", "-W", strconv.Itoa(max(1, (engine.cfg.TimeoutMS+999)/1000)), "-M", "do", "-s", strconv.Itoa(size-overhead), host)
		if err == nil {
			return true, false, nil
		}
		if probeCtx.Err() != nil {
			return false, false, probeCtx.Err()
		}
		output := strings.ToLower(string(data))
		if strings.Contains(output, "message too long") || strings.Contains(output, "frag needed") || strings.Contains(output, "packet too big") {
			return false, true, nil
		}
		return false, false, fmt.Errorf("ICMP probe did not establish reachability or an explicit packet-too-big result: %w", err)
	}
	lower, upper := measurement.MTUMin, measurement.MTUMax
	good, _, err := probe(lower)
	if err != nil || !good {
		check.Error = "Minimum-size ICMP probe failed; no MTU estimate is possible."
		check.DurationMS = elapsed(started)
		return check
	}
	check.MTU.LargestConfirmedBytes = lower
	for lower < upper {
		candidate := lower + (upper-lower+1)/2
		good, rejected, err := probe(candidate)
		if err != nil {
			check.Error = err.Error()
			check.DurationMS = elapsed(started)
			return check
		}
		if good {
			lower = candidate
			check.MTU.LargestConfirmedBytes = lower
		} else if rejected {
			check.MTU.SmallestRejectedBytes = candidate
			upper = candidate - 1
		}
	}
	check.MTU.Confidence = "bounded_estimate"
	if check.MTU.SmallestRejectedBytes == 0 {
		check.MTU.Confidence = "lower_bound"
	}
	check.Success, check.DurationMS = true, elapsed(started)
	return check
}
