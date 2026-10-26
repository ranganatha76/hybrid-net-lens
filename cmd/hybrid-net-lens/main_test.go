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
