# Hybrid Net Lens

A Go diagnostic agent for slow or unreliable connections between Kubernetes,
on-premises systems, and cloud environments. It turns bounded DNS, TCP, TLS, and
HTTP checks into timestamped JSON evidence and actionable findings.

Start with paid assessments; use the API with an external scheduler for recurring
checks. This is an initial single-tenant backend, not a hosted SaaS platform or a
replacement for packet captures and infrastructure logs.

## Quick Start

Requires Go 1.26.10 or newer (security-patched standard library). No external Go
library dependencies. Baseline checks need no elevated privileges; optional active
checks require `iperf3` and Linux iputils `ping`, included in the container image.

```sh
make check
make build
./bin/hybrid-net-lens validate -config config.example.json
export HYBRID_NET_LENS_TOKEN="$(openssl rand -hex 32)"
./bin/hybrid-net-lens serve -config config.example.json
```

The agent listens at `http://127.0.0.1:8080`. In a second terminal, use the same
token through your secret manager or terminal environment. Do not paste secrets
into shared logs, command histories, or tickets.

```sh
curl --fail-with-body http://127.0.0.1:8080/healthz
curl --fail-with-body -H "Authorization: Bearer ${HYBRID_NET_LENS_TOKEN}" \
  http://127.0.0.1:8080/api/v1/targets
curl --fail-with-body --max-time 40 \
  -H "Authorization: Bearer ${HYBRID_NET_LENS_TOKEN}" \
  -H 'Content-Type: application/json' \
  -d '{"target_id":"local-agent"}' \
  http://127.0.0.1:8080/api/v1/runs
```

The example checks the agent's own health endpoint only. For useful diagnostics,
replace its target and CIDR with an endpoint you own or have permission to test.
Restart the service after configuration changes.

To diagnose without starting an API or configuring a token:

```sh
./bin/hybrid-net-lens run -config config.example.json -target local-agent
```

`run` prints a JSON report and does not write to the report store. Exit codes:
`0` healthy, `2` failed/degraded/incomplete diagnostic, `1` usage/configuration/
startup/output error. CLI runs do not have the server's concurrency/cooldown
limits; bound external schedules yourself.

## Configuration

Copy `config.example.json` to ignored `config.local.json` and edit it. Unknown
fields and trailing JSON are rejected. There are no implicit configuration defaults.

| Field | Meaning |
| --- | --- |
| `listen` | API bind address; plaintext defaults to loopback only |
| `data_dir` | Report directory; created as 0700, must remain owner-only |
| `allowed_cidrs` | Explicit authorized destination networks; `/0` rejected |
| `timeout_ms` | Each DNS/connect/handshake/HTTP deadline, 50..10000 ms |
| `run_timeout_ms` | Whole-run deadline, from `timeout_ms` up to 120000 ms |
| `attempts` | TCP connections per resolved IP, 1..10 |
| `max_concurrent` | API in-flight diagnostic limit, 1..64 |
| `max_reports` | Retained report count, 1..100000; start with 1000 |
| `tls_cert_file`, `tls_key_file` | Optional paired API server certificate/key paths |
| `targets` | 1..256 fixed targets: `id`, `host`, `port`, `protocol` |

### Active Measurements

Active measurements are disabled unless a target contains `measurements`. They
generate test traffic, so obtain explicit authorization and account for cloud
egress costs. Use a fixed IP literal peer, authorize it in `allowed_cidrs`, and
run a firewall-restricted `iperf3 --server --port 5201` on that peer. The listener
is not a public service: restrict TCP and UDP 5201 to your diagnostic agents.

```json
{
  "id": "authorized-peer",
  "host": "10.20.0.10",
  "port": 5201,
  "protocol": "tcp",
  "measurements": {
    "throughput": true,
    "udp_loss": true,
    "mtu": true,
    "iperf_port": 5201,
    "duration_seconds": 2,
    "rate_mbps": 5,
    "mtu_min": 1280,
    "mtu_max": 1500
  }
}
```

Throughput is receiver-observed **upload goodput at the configured rate cap**,
not an uncapped link-capacity estimate. UDP delivery loss uses 1200-byte datagrams
and the receiver statistics reported by iperf3; host overload can cause loss too.
Each benchmark allows 1..10 seconds and 1..20 Mbps. The maximum configured payload
budget is approximately 25 MB per benchmark, excluding overhead/retransmissions;
TCP plus UDP can total approximately 50 MB. Rate pacing is not a hard byte quota.
One active measurement set runs at a time per process to limit self-interference.
Concurrent attempts receive a `MEASUREMENT_BUSY` finding, not a misleading result.

MTU checks send at most 14 ICMP echo probes with fragmentation disabled and search
an operator-selected 1280..9000-byte range. A successful ceiling is a **lower
bound**, not proof of the exact path MTU. An explicit packet-too-big/fragmentation
error brackets an estimate; a timeout is **inconclusive**. ICMP filtering, tunnels,
ECMP, and changing routes affect results. Linux datagram ping requires the process
GID in `net.ipv4.ping_group_range`; the chart configures GID 10001 without granting
NET_RAW. MTU checks require Linux; use the image for macOS development.

Configure a whole-run deadline large enough for baseline checks, both benchmarks,
and the MTU search. Short deadlines produce `incomplete` reports. Missing binaries
or unsupported platforms fail startup when their measurements are enabled. Remove
`measurements` or set the relevant booleans to false to roll back active behavior.

Protocols: `tcp`, `tls`, `http`, `https`. HTTP(S) also requires `path` and
`expected_status`. Configure only safe, idempotent GET health endpoints. HTTP
response bodies are not collected. Query strings and fragments are unsupported.
TLS validates the hostname and system trust store, with TLS 1.2 minimum; for
private PKI, install your CA or supply a complete trusted bundle via
`SSL_CERT_FILE`. There is no insecure certificate-bypass mode.

Every DNS answer must pass the allowlist before any connection starts. All
validated IPs are tested, up to 16 per target, without re-resolving at dial time.
Link-local, multicast, unspecified, and known cloud metadata/platform addresses
are blocked even when included in allowed networks. Use narrow CIDRs and an
independent egress firewall; application policy is not a complete network sandbox.
Loopback is permitted only when explicitly allowed, as in the local example.

## HTTP API

All diagnostic and metrics endpoints require `Authorization: Bearer <token>`.
The server loads a 32..512-character printable token at startup from exactly one
of `HYBRID_NET_LENS_TOKEN` or `HYBRID_NET_LENS_TOKEN_FILE`. Generate a random
token, mount the file read-only, and restart to rotate it. No token is embedded
in the image or configuration examples.

| Method / Path | Result |
| --- | --- |
| `GET /healthz` | Unauthenticated process liveness |
| `GET /readyz` | Unauthenticated report-storage write/sync readiness |
| `GET /api/v1/targets` | Configured target inventory |
| `POST /api/v1/runs` | `{"target_id":"..."}`; synchronous persisted report |
| `GET /api/v1/runs?limit=20` | Newest reports by file modification time; limit 1..100 |
| `GET /api/v1/runs/{id}` | Full retained report |
| `GET /metrics` | Authenticated Prometheus text metrics |

POST returns `201` when a report is saved, even when the diagnostic status is
`failed`. Inspect `status` and `findings`; HTTP success does not mean connectivity
is healthy. Other responses include `400`, `401`, `404`, `415`, `429` with
`Retry-After`, and `503`. Error bodies contain `error.code` and `error.message`.
Requests carry `X-Request-ID`. POST bodies are capped at 1024 bytes. Each target
has a five-second start-to-start cooldown, in addition to the global concurrency
limit. There is no waiting queue or automatic POST retry/idempotency support.

## Production Deployment

1. Obtain authorization for the probe endpoints. Deploy one agent per relevant
   vantage point; checks observe the agent's network namespace, not every pod's.
2. Configure precise destinations and safe health paths. Validate the config.
3. Use a dedicated unprivileged user and a persistent local filesystem supporting
   atomic rename and file/directory sync. Run only one process per report
   directory. Do not share it across replicas or use it as a multi-writer database.
4. Configure API TLS and a secret token file. Plaintext non-loopback binds fail
   unless `-allow-insecure-http` is explicitly passed for a trusted TLS proxy.
   In that case, firewall direct access to the backend and protect the proxy hop.
5. Enforce ingress/egress policy and restrict both unauthenticated health endpoints.
   Reports contain internal hostnames and addresses: encrypt disks/backups and
   restrict access. Cloud metadata cannot be exhaustively enumerated in software.
6. Schedule checks through a protected cron job, Kubernetes CronJob, or your
   existing monitoring system. Choose intervals above five seconds and avoid
   overlapping long runs. No scheduler or notification delivery is built in.
7. Scrape `/metrics` over verified TLS using a bearer-token credential file.
   Alert on storage errors, unhealthy target results, and stale/missing results.
8. Test the representative workload, storage failures, resource limits, TLS, and
   network policy before admitting production traffic.

### Container

```sh
docker build --build-arg VERSION=0.2.0 -t hybrid-net-lens:0.2.0 .
```

The Go binary is static; the Debian runtime is non-root (UID/GID 10001) and includes
the system CA bundle, iperf3, and iputils ping with file capabilities stripped.
Mount your config at `/etc/hybrid-net-lens/config.json`, a token file, TLS files,
and a writable persistent report directory. Set `HYBRID_NET_LENS_TOKEN_FILE` to
the mounted token path. Use `--read-only --cap-drop=ALL` and
`--security-opt=no-new-privileges`. Active iperf3 checks also require a bounded
writable `/tmp`, for example `--tmpfs /tmp:rw,noexec,nosuid,size=16m,mode=1777`.
For MTU tests, add `--sysctl 'net.ipv4.ping_group_range=10001 10001'`.
The host must prepare bind-volume ownership for UID 10001. Supply TLS when binding
the container to `0.0.0.0`. Named Docker data volumes inherit the image directory's
ownership; the end-to-end test verifies this with a read-only root filesystem.

The builder/runtime bases are pinned by verified multi-platform digests. Pin the
deployed application image by its registry digest too, and refresh base pins plus
security package layers regularly; cached package layers do not receive new fixes.

### Kubernetes

Use the Helm chart for production configuration rather than editing the legacy
example manifest. It requires explicit targets, CIDRs, and existing secret names:

```yaml
image:
  repository: your-registry/hybrid-net-lens
  tag: "0.2.0"
  digest: "" # Set the verified registry sha256 digest for a production release.
auth:
  existingSecret: hybrid-net-lens-auth
tls:
  existingSecret: hybrid-net-lens-tls
config:
  allowed_cidrs: ["10.20.0.10/32"]
  targets:
    - id: authorized-peer
      host: 10.20.0.10
      port: 5201
      protocol: tcp
      measurements:
        throughput: true
        udp_loss: true
        mtu: true
        iperf_port: 5201
        duration_seconds: 2
        rate_mbps: 5
        mtu_min: 1280
        mtu_max: 1500
```

Supply those environment-specific values from your deployment repository. The
auth secret needs a random `token`; the TLS secret needs `tls.crt`/`tls.key`, with
a certificate covering `<release>.<namespace>.svc` and the actual client hostname.
Prefer your secret manager and PKI; do not use the test CA in production.

```sh
helm upgrade --install hybrid-net-lens deploy/helm/hybrid-net-lens \
  --kube-context YOUR_APPROVED_CONTEXT --namespace hybrid-net-lens \
  --create-namespace --values /path/to/reviewed-values.yaml --wait --timeout 3m
```

The chart deploys one writer, `Recreate` upgrades, retained PVC, read-only root,
bounded memory-backed `/tmp`, startup/readiness/liveness probes, token/TLS secret
mounts, resource limits, and NetworkPolicy. Configuration changes roll the pod via
a checksum. Secret/certificate rotation currently needs an explicit rollout restart.
The PVC is retained on Helm uninstall; delete it only after an intentional data
retention decision. Back up reports before upgrades; `helm rollback` restores the
previous release configuration/image but cannot recover deleted retained reports.

External peers use the configured CIDRs at network-policy L3 (all protocols, to
allow ICMP). The application additionally restricts configured ports. Use narrow
CIDRs and, when needed, an upstream firewall for stricter port control. For peers
inside the same namespace, set `networkPolicy.peerPodLabels` to their precise
labels: Cilium does not treat pod IPs as external `ipBlock` destinations. This is
an additional authorization path; only label trusted peer pods. Ingress permits
only same-namespace pods matching `networkPolicy.clientPodLabels` by default.
Review DNS selectors for your cluster, especially NodeLocal DNS.

`deploy/kubernetes.yaml` is a hardened starting template, not a cluster-specific
installation. Before applying it:

- Replace the target IP, allowed CIDR, egress rule, and image with your values.
  Prefer a certificate-matching DNS name for TLS targets, authorizing all its IPs.
- Verify the cluster DNS labels/IPs and whether NodeLocal DNS requires different
  egress rules. Your CNI must actually enforce NetworkPolicy.
- Choose an available storage class and confirm fsGroup-supported volume ownership.
- Issue an API TLS certificate with the service DNS name in its SANs.
- Create `hybrid-net-lens-auth` with key `token` and `hybrid-net-lens-tls` as a
  Kubernetes TLS Secret in namespace `hybrid-net-lens`, using your secret manager.
- Allow only intended clients. The sample permits pods labeled
  `hybrid-net-lens-client=true` within the same namespace. It exposes no public ingress.

```sh
kubectl create namespace hybrid-net-lens --dry-run=client -o yaml | kubectl apply -f -
# Provision the two Secrets above before starting the agent.
kubectl apply -f deploy/kubernetes.yaml
kubectl -n hybrid-net-lens rollout status deployment/hybrid-net-lens
```

The deployment uses one replica and `Recreate`, so upgrades have a short outage.
The 50-second termination grace period covers the sample 30-second run deadline
plus drain time; increase it if you increase the deadline. Kubernetes HTTPS health
probes do not validate server certificates; independently verify API TLS from a client.

### Operations and Rollback

- Logs are structured JSON on stderr, without request bodies, tokens, or raw query
  strings. Reports remain on disk; there is no external telemetry exporter.
- Metrics reset at process restart, including last-result gauges. Absent results
  mean unknown, not healthy. Schedule an initial check and alert on missing/stale data.
- Retention deletes the oldest files when a new report is saved; this is intentional
  deletion, not archival. At most approximately `max_reports * 1 MiB` of final
  report data is retained, plus filesystem overhead and temporary writes. Monitor
  free space; aborted processes can leave `.report-*`/`.ready-*` files. Remove
  stale temp files only while the agent is stopped and after inspecting them.
- Stop the agent and snapshot the report volume before upgrades. Back up config
  separately; keep secrets in a secret manager. Test restoration periodically.
- Roll back by stopping the new process, restoring the prior image/config, and
  restarting against compatible schema-version-1 reports. No schema migration is
  performed by this version. Restore a snapshot only when necessary; that can
  discard reports created after the snapshot. Retention deletions require backups
  to recover. Future incompatible formats require an explicit migration plan.
- Token and certificate changes currently require restart. Synchronize clients
  during token rotation; overlapping keys and zero-downtime rotation are not implemented.

## Verification and Limits

```sh
make check
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out
make build VERSION=0.2.0
```

Unit tests use local servers; they do not scan external infrastructure. CI runs
tests, race detection, vet, formatting, a binary build, reachable-Go-vulnerability
scanning, an image build/scan, real container tests, and an isolated kind/Cilium gate.

This release supports opt-in UDP delivery-loss, upload throughput, and Linux DF
MTU measurements. It does **not** implement traceroute, packet capture, automatic
remediation, cross-agent comparison,
multi-tenancy/RBAC, a dashboard, billing, or managed alert delivery. TCP connection
failure ratios are not packet-loss statistics, and findings are evidence-backed
triage suggestions rather than guaranteed root-cause attribution. Production
readiness still requires your environment's security review, load/failure testing,
and deployment validation. See `DESIGN.md` for architecture and threat boundaries.

### Repeatable Release Gates

```sh
make security
make image VERSION=0.2.0 IMAGE=hybrid-net-lens:verify
make image-security IMAGE=hybrid-net-lens:verify
make integration IMAGE=hybrid-net-lens:verify
go install sigs.k8s.io/kind@v0.27.0
make cluster-check IMAGE=hybrid-net-lens:verify
```

The container gate generates temporary certificates and a token, checks verified
TLS/authentication, actual TCP/UDP/MTU probes, secret redaction, and report recovery
after restart. It automatically deletes its containers, network, and volumes.

The image-security gate uses a digest-pinned Trivy scanner and fails on fixable
HIGH/CRITICAL findings. That policy excludes unfixed advisories and lower
severities; it is not a claim that no vulnerabilities of any kind exist. The Go
gate separately checks reachable known vulnerabilities without that severity filter.

The cluster gate requires Docker, Helm, kubectl, kind, and internet access. It
creates a **new isolated kind cluster** with Cilium policy enforcement, validates
the chart, measurements, permitted/denied ingress and egress, and PVC persistence, then
deletes that cluster. It uses a dedicated ignored kubeconfig and never the selected
context. Set `KEEP_TEST_CLUSTER=1` only for debugging; this leaves local resources
running. The test refuses any context other than `kind-hybrid-net-lens-verify`.

These are automated release evidence, not permission to deploy to an existing
production cluster. Real endpoint ownership, PKI/secrets, registry credentials,
storage class, customer network policy, backup retention, and SLO/load acceptance
remain operator-controlled inputs that software cannot safely invent.

### Verified Release Baseline

On 2026-10-26, release `0.2.0` passed the Go/race/vet gates, a clean reachable Go
vulnerability scan using Go 1.26.10, the image-security policy above, real
non-root/read-only container tests, and a fresh Kubernetes 1.32.2 kind cluster with
Cilium 1.18.3. Cluster tests included trusted TLS, active measurements, denied and
permitted ingress/egress, and PVC recovery after rollout. Temporary test resources
were deleted; no changes were applied to the selected AKS context.

This validates the shipped implementation under that baseline, not your production
environment's capacity or SLOs. Run the same gates against a reviewed immutable
release image and your authorized staging topology before promotion.