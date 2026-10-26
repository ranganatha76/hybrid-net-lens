package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hybrid-net-lens/internal/config"
)

// TestListenerSecurity verifies the plaintext listener exposure restrictions.
// Literal IPv4 and IPv6 loopback listeners must work without TLS.
// Wildcard, private, empty-host, and hostname listeners must be rejected.
// An explicit insecure override must allow those otherwise rejected listeners.
// Configuring a TLS certificate must also satisfy the listener security gate.
func TestListenerSecurity(t *testing.T) {
	for _, address := range []string{"127.0.0.1:8080", "[::1]:8080"} {
		if err := validateListener(config.Config{Listen: address}, false); err != nil {
			t.Fatal(err)
		}
	}
	for _, address := range []string{"0.0.0.0:8080", ":8080", "10.0.0.1:8080", "localhost:8080"} {
		cfg := config.Config{Listen: address}
		if err := validateListener(cfg, false); err == nil {
			t.Fatalf("accepted %s", address)
		}
		if err := validateListener(cfg, true); err != nil {
			t.Fatal(err)
		}
		cfg.TLSCertFile = "cert.pem"
		if err := validateListener(cfg, false); err != nil {
			t.Fatal(err)
		}
	}
}

// TestTokenSources exercises token loading with isolated environment settings.
// It first verifies that the absence of both token sources is an error.
// A temporary owner-only token file supplies a value with trailing whitespace.
// Loading that file must produce the trimmed token without changing its value.
// Providing a direct token alongside the file must fail as ambiguous input.
func TestTokenSources(t *testing.T) {
	t.Setenv("HYBRID_NET_LENS_TOKEN", "")
	t.Setenv("HYBRID_NET_LENS_TOKEN_FILE", "")
	if _, err := loadToken(); err == nil {
		t.Fatal("accepted empty token")
	}
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("file-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HYBRID_NET_LENS_TOKEN_FILE", path)
	if token, err := loadToken(); err != nil || token != "file-token" {
		t.Fatal(token, err)
	}
	t.Setenv("HYBRID_NET_LENS_TOKEN", "environment-token")
	if _, err := loadToken(); err == nil {
		t.Fatal("accepted ambiguous token sources")
	}
}

// TestCommands checks command dispatch and basic CLI exit-code behavior.
// Missing commands and unknown commands must return a command error.
// A missing configuration file must fail before diagnostics are attempted.
// A run naming an unconfigured target must also return an error status.
// The version command must succeed and write the current version to stdout.
func TestCommands(t *testing.T) {
	for _, args := range [][]string{{}, {"unknown"}, {"validate", "-config", "missing.json"}, {"run", "-config", "../../config.example.json", "-target", "missing"}} {
		if code := execute(context.Background(), args, &bytes.Buffer{}, &bytes.Buffer{}); code != 1 {
			t.Fatalf("%v: %d", args, code)
		}
	}
	var output bytes.Buffer
	if code := execute(context.Background(), []string{"version"}, &output, &bytes.Buffer{}); code != 0 || !strings.Contains(output.String(), version) {
		t.Fatal(code, output.String())
	}
}
