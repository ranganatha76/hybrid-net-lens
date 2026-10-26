//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"hybrid-net-lens/internal/config"
	"hybrid-net-lens/internal/diagnostic"
)

// command runs an external integration-test tool with a three-minute deadline.
// Arguments are passed directly to the executable rather than through a shell.
// Combined stdout and stderr are captured for failure diagnostics.
// A nonzero exit or context failure immediately fails the calling test.
// Successful output is returned as text with leading and trailing whitespace removed.
func command(t *testing.T, name string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	output, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, output)
	}
	return strings.TrimSpace(string(output))
}

// cleanup performs a best-effort external cleanup action for integration resources.
// It uses a fresh background context so test-request cancellation cannot prevent cleanup.
// A 30-second deadline bounds a stalled container or cluster cleanup command.
// Arguments are executed directly without shell interpolation.
// Exit errors are ignored so cleanup does not replace the original test failure.
func cleanup(name string, args ...string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	exec.CommandContext(ctx, name, args...).Run()
}

// credentials creates temporary TLS material and a random bearer token for tests.
// It generates a short-lived P-256 certificate authority and signed server certificate.
// The leaf certificate covers loopback plus the caller's requested DNS identities.
// Certificate, key, CA, and token files are written inside the test's temporary directory.
// It returns that directory, an isolated CA trust pool, and the token for API requests.
func credentials(t *testing.T, names []string) (string, *x509.CertPool, string) {
	t.Helper()
	dir := t.TempDir()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Hybrid Net Lens isolated test CA"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: names, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	certDER, err := x509.CreateCertificate(rand.Reader, cert, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	token := rand.Text() + rand.Text()
	for name, data := range map[string][]byte{
		"tls.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		"tls.key": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		"ca.crt":  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		"token":   []byte(token),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0444); err != nil {
			t.Fatal(err)
		}
	}
	roots := x509.NewCertPool()
	parsedCA, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(parsedCA)
	return dir, roots, token
}

// clientFor constructs an HTTPS client that trusts the supplied test CA pool.
// Normal certificate verification remains enabled with TLS 1.2 as the minimum version.
// A 45-second timeout bounds each full HTTP operation.
// Keep-alives are disabled so requests use fresh transport connections.
// The returned client is used for readiness, authentication, report, and metrics checks.
func clientFor(roots *x509.CertPool) *http.Client {
	return &http.Client{Timeout: 45 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DisableKeepAlives: true}}
}

// request sends a JSON integration request and asserts its expected HTTP status.
// It builds the request from the supplied method, URL, and optional body bytes.
// Nonempty tokens are attached as Bearer credentials without logging them here.
// The response body is closed after reading at most 2 MiB into memory.
// Transport, read, or status failures fail the test; success returns the response bytes.
func request(t *testing.T, client *http.Client, method, address, token string, body []byte, status int) []byte {
	t.Helper()
	input, err := http.NewRequest(method, address, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		input.Header.Set("Authorization", "Bearer "+token)
	}
	input.Header.Set("Content-Type", "application/json")
	response, err := client.Do(input)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != status {
		t.Fatalf("%s returned %d, expected %d: %s", address, response.StatusCode, status, data)
	}
	return data
}

// awaitReady waits for an integration service to return 200 from its readiness route.
// A 200-millisecond ticker spaces repeated HTTPS readiness requests.
// Connection errors and non-200 responses are retried while the wait context allows.
// Every received response body is closed to avoid leaking connections during startup.
// A 45-second wait context ends the loop with a test failure when readiness never arrives.
func awaitReady(t *testing.T, client *http.Client, address string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			t.Fatal("readiness deadline exceeded")
		case <-ticker.C:
			response, err := client.Get(address + "/readyz")
			if err != nil {
				continue
			}
			response.Body.Close()
			if response.StatusCode == 200 {
				return
			}
		}
	}
}

// TestContainerEndToEnd verifies the built image in an isolated Docker environment.
// It provisions a private iperf peer, temporary TLS credentials, and persistent volumes.
// The agent runs non-root with a read-only root filesystem and all capabilities dropped.
// Requests verify TLS, authentication, TCP, throughput, UDP loss, and MTU evidence.
// Restart recovery, protected metrics, token-log redaction, and resource cleanup complete the test.
func TestContainerEndToEnd(t *testing.T) {
	image := os.Getenv("HYBRID_NET_LENS_TEST_IMAGE")
	if image == "" {
		t.Fatal("set HYBRID_NET_LENS_TEST_IMAGE to the built image")
	}
	command(t, "docker", "info", "--format", "{{.ServerVersion}}")
	name := "hnl-test-" + strings.ToLower(rand.Text()[:10])
	command(t, "docker", "network", "create", name)
	t.Cleanup(func() { cleanup("docker", "network", "rm", name) })
	command(t, "docker", "volume", "create", name)
	t.Cleanup(func() { cleanup("docker", "volume", "rm", name) })
	command(t, "docker", "run", "-d", "--name", name+"-peer", "--network", name, "--cap-drop=ALL", "--security-opt=no-new-privileges", "--entrypoint", "iperf3", image, "--server", "--port", "5201")
	t.Cleanup(func() { cleanup("docker", "rm", "-f", name+"-peer") })
	peer := command(t, "docker", "inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name+"-peer")
	dir, roots, token := credentials(t, []string{"localhost"})
	cfg := config.Config{Listen: "0.0.0.0:8080", DataDir: "/data/reports", AllowedCIDRs: []string{peer + "/32"}, TimeoutMS: 2000, RunTimeoutMS: 30000, Attempts: 1, MaxConcurrent: 2, MaxReports: 10, TLSCertFile: "/etc/hybrid-net-lens/tls.crt", TLSKeyFile: "/etc/hybrid-net-lens/tls.key", Targets: []config.Target{{ID: "peer", Host: peer, Port: 5201, Protocol: "tcp", Measurements: &config.Measurements{Throughput: true, UDPLoss: true, MTU: true, IPerfPort: 5201, DurationSeconds: 1, RateMbps: 2, MTUMin: 1280, MTUMax: 1500}}}}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), data, 0444); err != nil {
		t.Fatal(err)
	}
	command(t, "docker", "volume", "create", name+"-config")
	t.Cleanup(func() { cleanup("docker", "volume", "rm", name+"-config") })
	command(t, "docker", "create", "--name", name+"-init", "--mount", "type=volume,source="+name+"-config,target=/etc/hybrid-net-lens", image, "version")
	t.Cleanup(func() { cleanup("docker", "rm", "-f", name+"-init") })
	for _, file := range []string{"config.json", "tls.crt", "tls.key", "token"} {
		command(t, "docker", "cp", filepath.Join(dir, file), name+"-init:/etc/hybrid-net-lens/"+file)
	}
	command(t, "docker", "create", "--name", name, "--network", name, "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--sysctl", "net.ipv4.ping_group_range=10001 10001", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m,mode=1777", "--mount", "type=volume,source="+name+",target=/data", "--mount", "type=volume,source="+name+"-config,target=/etc/hybrid-net-lens,readonly", "--publish", "127.0.0.1::8080", "--env", "HYBRID_NET_LENS_TOKEN_FILE=/etc/hybrid-net-lens/token", image)
	t.Cleanup(func() {
		if t.Failed() {
			t.Log(command(t, "docker", "logs", name))
		}
		cleanup("docker", "rm", "-f", name)
	})
	command(t, "docker", "start", name)
	address := "https://" + command(t, "docker", "port", name, "8080/tcp")
	client := clientFor(roots)
	awaitReady(t, client, address)
	request(t, client, "GET", address+"/api/v1/targets", "", nil, 401)
	body := request(t, client, "POST", address+"/api/v1/runs", token, []byte(`{"target_id":"peer"}`), 201)
	var report diagnostic.Report
	if err := json.Unmarshal(body, &report); err != nil {
		t.Fatal(err)
	}
	if report.Status != "healthy" {
		t.Fatalf("unhealthy report: %s", body)
	}
	phases := map[string]bool{}
	for _, check := range report.Checks {
		phases[check.Phase] = check.Success
	}
	for _, phase := range []string{"tcp", "throughput", "udp_loss", "mtu"} {
		if !phases[phase] {
			t.Fatalf("missing successful %s: %s", phase, body)
		}
	}
	command(t, "docker", "stop", "--time", "40", name)
	command(t, "docker", "start", name)
	address = "https://" + command(t, "docker", "port", name, "8080/tcp")
	awaitReady(t, client, address)
	request(t, client, "GET", address+"/api/v1/runs/"+report.ID, token, nil, 200)
	request(t, client, "GET", address+"/metrics", token, nil, 200)
	logs := command(t, "docker", "logs", name)
	if strings.Contains(logs, token) {
		t.Fatal("token leaked to logs")
	}
	t.Logf("Verified TLS, auth, TCP, throughput, UDP delivery loss, MTU, restart persistence, and token redaction; report %s", report.ID)
}

// Example_measurementBudget illustrates the maximum configured benchmark payload budget.
// It uses the allowed upper rate of 20 megabits per second over ten seconds.
// Dividing the resulting megabit total by eight expresses the nominal payload in megabytes.
// The example describes one benchmark rather than total wire overhead or all tests combined.
// Its expected-output assertion keeps the displayed budget explanation executable.
func Example_measurementBudget() {
	fmt.Println("20 Mbps * 10 seconds / 8 = 25 MB maximum target payload per benchmark")
	// Output: 20 Mbps * 10 seconds / 8 = 25 MB maximum target payload per benchmark
}
