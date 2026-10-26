package config

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicy(t *testing.T) {
	policy, err := NewPolicy([]string{"10.0.0.0/8", "127.0.0.1/32", "169.254.0.0/16", "100.64.0.0/10", "168.63.129.16/32", "fd00::/8", "224.0.0.0/4"})
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"10.1.2.3", "127.0.0.1", "::ffff:10.1.2.3", "fd00::1"} {
		if !policy.Allows(netip.MustParseAddr(value)) {
			t.Errorf("expected allowed: %s", value)
		}
	}
	for _, value := range []string{"8.8.8.8", "169.254.169.254", "100.100.100.200", "168.63.129.16", "fd00:ec2::254", "224.0.0.1", "0.0.0.0"} {
		if policy.Allows(netip.MustParseAddr(value)) {
			t.Errorf("expected denied: %s", value)
		}
	}
	for _, cidr := range []string{"0.0.0.0/0", "::/0", "::ffff:10.0.0.0/104", "invalid"} {
		if _, err := NewPolicy([]string{cidr}); err == nil {
			t.Errorf("accepted %s", cidr)
		}
	}
}

func TestLoadStrict(t *testing.T) {
	for _, content := range []string{`{"unknown":1}`, `{} {}`, `{"listen": 3}`, "{}" + strings.Repeat(" ", 1<<20)} {
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Errorf("accepted %s", content)
		}
	}
}

func TestValidate(t *testing.T) {
	valid := Config{Listen: "127.0.0.1:8080", DataDir: "data", AllowedCIDRs: []string{"127.0.0.1/32"}, TimeoutMS: 100, RunTimeoutMS: 1000, Attempts: 2, MaxConcurrent: 2, MaxReports: 10, Targets: []Target{{ID: "local", Host: "localhost", Port: 443, Protocol: "https", Path: "/health", ExpectedStatus: 200}}}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Config){
		func(cfg *Config) { cfg.Listen = "127.0.0.1:invalid" },
		func(cfg *Config) { cfg.Attempts = 0 },
		func(cfg *Config) { cfg.TLSCertFile = "cert.pem" },
		func(cfg *Config) { cfg.Targets = append(cfg.Targets, cfg.Targets[0]) },
		func(cfg *Config) { cfg.Targets = []Target{{ID: "bad", Host: "host/path", Port: 80, Protocol: "tcp"}} },
		func(cfg *Config) {
			cfg.Targets = []Target{{ID: "bad", Host: "localhost", Port: 80, Protocol: "http", Path: "//evil", ExpectedStatus: 200}}
		},
	} {
		candidate := valid
		mutate(&candidate)
		if err := candidate.Validate(); err == nil {
			t.Error("accepted invalid config")
		}
	}
}

func TestMeasurementBudgets(t *testing.T) {
	valid := Measurements{Throughput: true, UDPLoss: true, MTU: true, IPerfPort: 5201, DurationSeconds: 2, RateMbps: 5, MTUMin: 1280, MTUMax: 1500}
	if err := valid.Validate("10.0.0.10"); err != nil {
		t.Fatal(err)
	}
	if err := valid.Validate("peer.example"); err == nil {
		t.Fatal("accepted unpinned measurement peer")
	}
	for _, mutate := range []func(*Measurements){
		func(value *Measurements) { value.RateMbps = 21 },
		func(value *Measurements) { value.DurationSeconds = 0 },
		func(value *Measurements) { value.IPerfPort = 0 },
		func(value *Measurements) { value.MTUMax = 9001 },
		func(value *Measurements) { value.MTUMin = 1000 },
	} {
		candidate := valid
		mutate(&candidate)
		if err := candidate.Validate("10.0.0.10"); err == nil {
			t.Fatal("accepted unsafe measurement budget")
		}
	}
	if err := (Measurements{}).Validate("127.0.0.1"); err == nil {
		t.Fatal("accepted empty measurements")
	}
}
