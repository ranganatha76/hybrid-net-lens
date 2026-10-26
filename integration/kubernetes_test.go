//go:build integration

package integration

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"hybrid-net-lens/internal/config"
	"hybrid-net-lens/internal/diagnostic"
)

func writeJSONFile(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func testPod(name, image string, labels map[string]string, args []string) map[string]any {
	return map[string]any{
		"apiVersion": "v1", "kind": "Pod", "metadata": map[string]any{"name": name, "labels": labels},
		"spec": map[string]any{
			"automountServiceAccountToken": false,
			"securityContext":              map[string]any{"runAsNonRoot": true, "runAsUser": 10001, "runAsGroup": 10001, "seccompProfile": map[string]string{"type": "RuntimeDefault"}},
			"containers": []any{map[string]any{
				"name": "test", "image": image, "imagePullPolicy": "IfNotPresent", "command": args,
				"securityContext": map[string]any{"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true, "capabilities": map[string]any{"drop": []string{"ALL"}}},
				"volumeMounts":    []any{map[string]string{"name": "temporary", "mountPath": "/tmp"}},
			}},
			"volumes": []any{map[string]any{"name": "temporary", "emptyDir": map[string]string{"medium": "Memory", "sizeLimit": "16Mi"}}},
		},
	}
}

func TestKubernetesDeployment(t *testing.T) {
	kubeconfig := os.Getenv("HYBRID_NET_LENS_TEST_KUBECONFIG")
	if kubeconfig == "" {
		t.Skip("isolated cluster test requires HYBRID_NET_LENS_TEST_KUBECONFIG")
	}
	kube := func(args ...string) string {
		return command(t, "kubectl", append([]string{"--kubeconfig", kubeconfig}, args...)...)
	}
	if current := kube("config", "current-context"); current != "kind-hybrid-net-lens-verify" {
		t.Fatalf("refusing non-test context %q", current)
	}
	image := os.Getenv("HYBRID_NET_LENS_TEST_IMAGE")
	if image == "" {
		t.Fatal("HYBRID_NET_LENS_TEST_IMAGE is required")
	}
	namespace := "hnl-" + strings.ToLower(rand.Text()[:10])
	kube("create", "namespace", namespace)
	t.Cleanup(func() {
		cleanup("kubectl", "--kubeconfig", kubeconfig, "delete", "namespace", namespace, "--wait=false")
	})
	kube("label", "namespace", namespace, "pod-security.kubernetes.io/enforce=restricted")
	dir, roots, token := credentials(t, []string{"agent." + namespace + ".svc"})
	kube("-n", namespace, "create", "secret", "generic", "agent-auth", "--from-file=token="+filepath.Join(dir, "token"))
	kube("-n", namespace, "create", "secret", "tls", "agent-tls", "--cert="+filepath.Join(dir, "tls.crt"), "--key="+filepath.Join(dir, "tls.key"))
	for _, name := range []string{"peer", "allowed", "denied"} {
		labels := map[string]string{}
		args := []string{"/bin/sleep", "3600"}
		if name == "allowed" {
			labels["hybrid-net-lens-client"] = "true"
		}
		if name == "peer" || name == "denied" {
			args = []string{"iperf3", "--server", "--port", "5201"}
		}
		if name == "peer" {
			labels["hybrid-net-lens-peer"] = "true"
		}
		path := filepath.Join(dir, name+".json")
		writeJSONFile(t, path, testPod(name, image, labels, args))
		kube("-n", namespace, "apply", "-f", path)
		kube("-n", namespace, "wait", "--for=condition=Ready", "pod/"+name, "--timeout=120s")
	}
	peer := kube("-n", namespace, "get", "pod", "peer", "-o", "jsonpath={.status.podIP}")
	if net.ParseIP(peer) == nil {
		t.Fatal("invalid peer IP")
	}
	separator := strings.LastIndex(image, ":")
	if separator < 1 {
		t.Fatal("test image must have explicit tag")
	}
	values := map[string]any{
		"image": map[string]string{"repository": image[:separator], "tag": image[separator+1:], "pullPolicy": "Never"},
		"auth":  map[string]string{"existingSecret": "agent-auth"}, "tls": map[string]string{"existingSecret": "agent-tls"},
		"networkPolicy": map[string]any{"peerPodLabels": map[string]string{"hybrid-net-lens-peer": "true"}},
		"config":        map[string]any{"allowed_cidrs": []string{peer + "/32"}, "attempts": 1, "targets": []config.Target{{ID: "peer", Host: peer, Port: 5201, Protocol: "tcp", Measurements: &config.Measurements{Throughput: true, UDPLoss: true, MTU: true, IPerfPort: 5201, DurationSeconds: 1, RateMbps: 2, MTUMin: 1280, MTUMax: 1500}}}},
	}
	valuesPath := filepath.Join(dir, "values.json")
	writeJSONFile(t, valuesPath, values)
	command(t, "helm", "--kubeconfig", kubeconfig, "upgrade", "--install", "agent", "../deploy/helm/hybrid-net-lens", "--namespace", namespace, "--values", valuesPath, "--wait", "--timeout=120s")
	t.Cleanup(func() {
		if t.Failed() {
			t.Log(kube("-n", namespace, "get", "pods", "-o", "wide"))
			t.Log(kube("-n", namespace, "logs", "deployment/agent"))
		}
	})
	forward := func() string {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := listener.Addr().(*net.TCPAddr).Port
		listener.Close()
		ctx, cancel := context.WithCancel(context.Background())
		process := exec.CommandContext(ctx, "kubectl", "--kubeconfig", kubeconfig, "-n", namespace, "port-forward", "service/agent", strconv.Itoa(port)+":8080", "--address=127.0.0.1")
		if err := process.Start(); err != nil {
			cancel()
			t.Fatal(err)
		}
		t.Cleanup(func() { cancel(); process.Wait() })
		address := fmt.Sprintf("https://127.0.0.1:%d", port)
		awaitReady(t, clientFor(roots), address)
		return address
	}
	address := forward()
	client := clientFor(roots)
	request(t, client, "GET", address+"/api/v1/targets", "", nil, 401)
	data := request(t, client, "POST", address+"/api/v1/runs", token, []byte(`{"target_id":"peer"}`), 201)
	var report diagnostic.Report
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.Status != "healthy" && report.Status != "degraded" {
		t.Fatalf("failed Kubernetes measurements: %s", data)
	}
	for _, phase := range []string{"throughput", "udp_loss", "mtu"} {
		found := false
		for _, check := range report.Checks {
			if check.Phase == phase && check.Success {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing %s: %s", phase, data)
		}
	}
	ip := kube("-n", namespace, "get", "pods", "-l", "app.kubernetes.io/instance=agent", "-o", "jsonpath={.items[0].status.podIP}")
	if net.ParseIP(ip) == nil {
		t.Fatal("invalid agent IP")
	}
	connect := "exec 3<>/dev/tcp/" + ip + "/8080"
	kube("-n", namespace, "exec", "allowed", "--", "/usr/bin/timeout", "4", "/bin/bash", "-c", connect)
	expectTimeout := func(pod, expression string) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		process := exec.CommandContext(ctx, "kubectl", "--kubeconfig", kubeconfig, "-n", namespace, "exec", pod, "--", "/usr/bin/timeout", "4", "/bin/bash", "-c", expression)
		output, err := process.CombinedOutput()
		var exited *exec.ExitError
		if !errors.As(err, &exited) || exited.ExitCode() != 124 {
			t.Fatalf("expected policy timeout from %s, got %v: %s", pod, err, output)
		}
	}
	expectTimeout("denied", connect)
	deniedIP := kube("-n", namespace, "get", "pod", "denied", "-o", "jsonpath={.status.podIP}")
	if net.ParseIP(deniedIP) == nil {
		t.Fatal("invalid unauthorized-peer IP")
	}
	connect = "exec 3<>/dev/tcp/" + deniedIP + "/5201"
	kube("-n", namespace, "exec", "allowed", "--", "/usr/bin/timeout", "4", "/bin/bash", "-c", connect)
	agentPod := kube("-n", namespace, "get", "pods", "-l", "app.kubernetes.io/instance=agent", "-o", "jsonpath={.items[0].metadata.name}")
	expectTimeout(agentPod, connect)
	kube("-n", namespace, "rollout", "restart", "deployment/agent")
	kube("-n", namespace, "rollout", "status", "deployment/agent", "--timeout=120s")
	address = forward()
	request(t, client, "GET", address+"/api/v1/runs/"+report.ID, token, nil, 200)
	t.Log("Verified Helm rollout, trusted TLS, active measurements, allowed/denied ingress and egress, and PVC persistence")
}
