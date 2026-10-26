package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"hybrid-net-lens/internal/api"
	"hybrid-net-lens/internal/config"
	"hybrid-net-lens/internal/diagnostic"
	"hybrid-net-lens/internal/store"
)

var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(execute(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func execute(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "Usage: hybrid-net-lens <validate|run|serve|version> [flags]")
		return 1
	}
	if args[0] == "version" {
		fmt.Fprintln(stdout, version)
		return 0
	}
	command := args[0]
	if command != "validate" && command != "run" && command != "serve" {
		fmt.Fprintln(stderr, "Unknown command:", command)
		return 1
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "config.example.json", "Path to strict JSON configuration")
	var targetID *string
	var insecure *bool
	if command == "run" {
		targetID = flags.String("target", "", "Configured target ID (required)")
	}
	if command == "serve" {
		insecure = flags.Bool("allow-insecure-http", false, "Allow non-loopback HTTP only behind a trusted TLS proxy")
	}
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 1
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "Unexpected positional arguments")
		return 1
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(stderr, "Configuration error:", err)
		return 1
	}
	if command == "validate" {
		fmt.Fprintln(stdout, "Configuration is valid.")
		return 0
	}
	if err := diagnostic.CheckDependencies(cfg); err != nil {
		fmt.Fprintln(stderr, "Probe dependency error:", err)
		return 1
	}
	vantage, err := os.Hostname()
	if err != nil {
		fmt.Fprintln(stderr, "Cannot determine hostname:", err)
		return 1
	}
	engine, err := diagnostic.New(cfg, vantage)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if command == "run" {
		for _, target := range cfg.Targets {
			if target.ID != *targetID {
				continue
			}
			report := engine.Run(ctx, target)
			encoder := json.NewEncoder(stdout)
			encoder.SetIndent("", "  ")
			if err := encoder.Encode(report); err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
			if report.Status != "healthy" {
				return 2
			}
			return 0
		}
		fmt.Fprintln(stderr, "Specify a configured target with -target")
		return 1
	}
	logger := slog.New(slog.NewJSONHandler(stderr, nil))
	if err := serve(ctx, cfg, engine, *insecure, logger); err != nil {
		logger.Error("server stopped", "error", err)
		return 1
	}
	return 0
}

func serve(ctx context.Context, cfg config.Config, engine *diagnostic.Engine, insecure bool, logger *slog.Logger) error {
	if err := validateListener(cfg, insecure); err != nil {
		return err
	}
	token, err := loadToken()
	if err != nil {
		return err
	}
	storage, err := store.New(cfg.DataDir, cfg.MaxReports)
	if err != nil {
		return fmt.Errorf("initialize reports: %w", err)
	}
	service, err := api.New(cfg, engine, storage, token, logger)
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr: cfg.Listen, Handler: service.Handler(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: cfg.RunTimeout() + 10*time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 16384, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}
	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	if insecure {
		logger.Warn("insecure HTTP override enabled; restrict ingress and terminate TLS upstream")
	}
	logger.Info("listening", "address", listener.Addr().String(), "tls", cfg.TLSCertFile != "", "version", version)
	finished := make(chan error, 1)
	go func() {
		if cfg.TLSCertFile != "" {
			finished <- server.ServeTLS(listener, cfg.TLSCertFile, cfg.TLSKeyFile)
		} else {
			finished <- server.Serve(listener)
		}
	}()
	select {
	case err := <-finished:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		logger.Info("draining requests")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.RunTimeout()+10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			server.Close()
			return fmt.Errorf("shutdown: %w", err)
		}
		err := <-finished
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}

func validateListener(cfg config.Config, insecure bool) error {
	if cfg.TLSCertFile != "" || insecure {
		return nil
	}
	host, _, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		return err
	}
	address, err := netip.ParseAddr(host)
	if err != nil || !address.IsLoopback() {
		return errors.New("non-loopback listeners require TLS; use -allow-insecure-http only behind a trusted TLS proxy")
	}
	return nil
}

func loadToken() (string, error) {
	value := os.Getenv("HYBRID_NET_LENS_TOKEN")
	path := os.Getenv("HYBRID_NET_LENS_TOKEN_FILE")
	if value != "" && path != "" {
		return "", errors.New("set only one of HYBRID_NET_LENS_TOKEN and HYBRID_NET_LENS_TOKEN_FILE")
	}
	if path != "" {
		file, err := os.Open(path)
		if err != nil {
			return "", fmt.Errorf("read API token: %w", err)
		}
		defer file.Close()
		data, err := io.ReadAll(io.LimitReader(file, 4097))
		if err != nil || len(data) > 4096 {
			return "", errors.New("cannot read token or token file exceeds 4096 bytes")
		}
		value = strings.TrimSpace(string(data))
	}
	if value == "" {
		return "", errors.New("HYBRID_NET_LENS_TOKEN or HYBRID_NET_LENS_TOKEN_FILE is required")
	}
	return value, nil
}
