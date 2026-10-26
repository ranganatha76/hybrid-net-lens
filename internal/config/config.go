package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Listen        string   `json:"listen"`
	DataDir       string   `json:"data_dir"`
	AllowedCIDRs  []string `json:"allowed_cidrs"`
	TimeoutMS     int      `json:"timeout_ms"`
	RunTimeoutMS  int      `json:"run_timeout_ms"`
	Attempts      int      `json:"attempts"`
	MaxConcurrent int      `json:"max_concurrent"`
	MaxReports    int      `json:"max_reports"`
	TLSCertFile   string   `json:"tls_cert_file,omitempty"`
	TLSKeyFile    string   `json:"tls_key_file,omitempty"`
	Targets       []Target `json:"targets"`
}

type Target struct {
	ID             string        `json:"id"`
	Host           string        `json:"host"`
	Port           int           `json:"port"`
	Protocol       string        `json:"protocol"`
	Path           string        `json:"path,omitempty"`
	ExpectedStatus int           `json:"expected_status,omitempty"`
	Measurements   *Measurements `json:"measurements,omitempty"`
}

type Measurements struct {
	Throughput      bool `json:"throughput,omitempty"`
	UDPLoss         bool `json:"udp_loss,omitempty"`
	MTU             bool `json:"mtu,omitempty"`
	IPerfPort       int  `json:"iperf_port,omitempty"`
	DurationSeconds int  `json:"duration_seconds,omitempty"`
	RateMbps        int  `json:"rate_mbps,omitempty"`
	MTUMin          int  `json:"mtu_min,omitempty"`
	MTUMax          int  `json:"mtu_max,omitempty"`
}

func (measurement Measurements) Validate(host string) error {
	if _, err := netip.ParseAddr(host); err != nil {
		return errors.New("active measurements require a fixed IP literal peer")
	}
	if !measurement.Throughput && !measurement.UDPLoss && !measurement.MTU {
		return errors.New("enable at least one active measurement")
	}
	if measurement.Throughput || measurement.UDPLoss {
		if measurement.IPerfPort < 1 || measurement.IPerfPort > 65535 || measurement.DurationSeconds < 1 || measurement.DurationSeconds > 10 || measurement.RateMbps < 1 || measurement.RateMbps > 20 {
			return errors.New("iperf_port must be 1..65535, duration_seconds 1..10, rate_mbps 1..20")
		}
	} else if measurement.IPerfPort != 0 || measurement.DurationSeconds != 0 || measurement.RateMbps != 0 {
		return errors.New("iperf fields require throughput or udp_loss")
	}
	if measurement.MTU {
		if measurement.MTUMin < 1280 || measurement.MTUMax < measurement.MTUMin || measurement.MTUMax > 9000 {
			return errors.New("MTU search must satisfy 1280 <= mtu_min <= mtu_max <= 9000")
		}
	} else if measurement.MTUMin != 0 || measurement.MTUMax != 0 {
		return errors.New("MTU bounds require mtu enabled")
	}
	return nil
}

var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)
var hostname = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?$`)

func Load(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil {
		return Config{}, err
	}
	if len(data) > 1<<20 {
		return Config{}, errors.New("config exceeds 1 MiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var cfg Config
	if err := decoder.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("decode config: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return cfg, errors.New("config must contain exactly one JSON object")
	}
	return cfg, cfg.Validate()
}

func (cfg Config) Validate() error {
	_, portValue, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen must be host:port: %w", err)
	}
	port, err := strconv.Atoi(portValue)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("listen port must be 1..65535")
	}
	if cfg.DataDir == "" {
		return errors.New("data_dir is required")
	}
	if cfg.TimeoutMS < 50 || cfg.TimeoutMS > 10000 || cfg.RunTimeoutMS < cfg.TimeoutMS || cfg.RunTimeoutMS > 120000 {
		return errors.New("timeout_ms must be 50..10000; run_timeout_ms must be timeout_ms..120000")
	}
	if cfg.Attempts < 1 || cfg.Attempts > 10 || cfg.MaxConcurrent < 1 || cfg.MaxConcurrent > 64 || cfg.MaxReports < 1 || cfg.MaxReports > 100000 {
		return errors.New("attempts must be 1..10, max_concurrent 1..64, max_reports 1..100000")
	}
	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return errors.New("tls_cert_file and tls_key_file must be set together")
	}
	if _, err := NewPolicy(cfg.AllowedCIDRs); err != nil {
		return err
	}
	if len(cfg.Targets) == 0 || len(cfg.Targets) > 256 {
		return errors.New("configure 1..256 targets")
	}
	seen := make(map[string]bool)
	for _, target := range cfg.Targets {
		if !identifier.MatchString(target.ID) || seen[target.ID] {
			return fmt.Errorf("invalid or duplicate target ID %q", target.ID)
		}
		seen[target.ID] = true
		if address, err := netip.ParseAddr(target.Host); err == nil {
			if address.Zone() != "" {
				return errors.New("scoped addresses are unsupported")
			}
		} else if len(target.Host) > 253 || !hostname.MatchString(target.Host) || strings.Contains(target.Host, "..") {
			return fmt.Errorf("invalid hostname for %s", target.ID)
		}
		if target.Port < 1 || target.Port > 65535 {
			return fmt.Errorf("invalid port for %s", target.ID)
		}
		switch target.Protocol {
		case "tcp", "tls", "http", "https":
		default:
			return fmt.Errorf("invalid protocol for %s", target.ID)
		}
		if target.Protocol == "http" || target.Protocol == "https" {
			if !strings.HasPrefix(target.Path, "/") || strings.HasPrefix(target.Path, "//") || strings.ContainsAny(target.Path, "?#\r\n") || target.ExpectedStatus < 100 || target.ExpectedStatus > 599 {
				return fmt.Errorf("%s requires an absolute path without query/fragment and expected_status 100..599", target.ID)
			}
		} else if target.Path != "" || target.ExpectedStatus != 0 {
			return fmt.Errorf("HTTP fields are not valid for %s", target.ID)
		}
		if target.Measurements != nil {
			if err := target.Measurements.Validate(target.Host); err != nil {
				return fmt.Errorf("%s: %w", target.ID, err)
			}
		}
	}
	return nil
}

func (cfg Config) Timeout() time.Duration { return time.Duration(cfg.TimeoutMS) * time.Millisecond }
func (cfg Config) RunTimeout() time.Duration {
	return time.Duration(cfg.RunTimeoutMS) * time.Millisecond
}

type Policy struct {
	prefixes []netip.Prefix
}

func NewPolicy(cidrs []string) (Policy, error) {
	if len(cidrs) == 0 || len(cidrs) > 256 {
		return Policy{}, errors.New("allowed_cidrs must contain 1..256 explicit networks")
	}
	policy := Policy{}
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil || prefix.Bits() == 0 || prefix.Addr().Is4In6() {
			return Policy{}, fmt.Errorf("invalid or unrestricted CIDR %q", cidr)
		}
		policy.prefixes = append(policy.prefixes, prefix.Masked())
	}
	return policy, nil
}

func (policy Policy) Allows(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsValid() || address.Zone() != "" || address.IsUnspecified() || address.IsMulticast() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address == netip.MustParseAddr("255.255.255.255") || address == netip.MustParseAddr("100.100.100.200") || address == netip.MustParseAddr("168.63.129.16") || address == netip.MustParseAddr("fd00:ec2::254") {
		return false
	}
	for _, prefix := range policy.prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}
