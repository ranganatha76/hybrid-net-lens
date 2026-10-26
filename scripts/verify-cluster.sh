#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
kind_bin="${KIND_BIN:-$(go env GOPATH)/bin/kind}"
image="${HYBRID_NET_LENS_TEST_IMAGE:-hybrid-net-lens:verify}"
cluster="hybrid-net-lens-verify"
mkdir -p .test-env
chmod 700 .test-env
kubeconfig="$PWD/.test-env/kubeconfig"
if "$kind_bin" get clusters | grep -qx "$cluster"; then
  printf '%s\n' "Refusing to overwrite existing test cluster $cluster" >&2
  exit 1
fi
cleanup() {
  if [[ "${KEEP_TEST_CLUSTER:-0}" != "1" ]]; then
    "$kind_bin" delete cluster --name "$cluster" --kubeconfig "$kubeconfig"
    rm -f "$kubeconfig"
  fi
}
trap cleanup EXIT
"$kind_bin" create cluster --name "$cluster" --config deploy/kind.yaml --kubeconfig "$kubeconfig"
chmod 600 "$kubeconfig"
helm --kubeconfig "$kubeconfig" upgrade --install cilium cilium \
  --repo https://helm.cilium.io --version 1.18.3 --namespace kube-system \
  --set ipam.mode=kubernetes --set kubeProxyReplacement=false \
  --set operator.replicas=1 --wait --timeout 5m
kubectl --kubeconfig "$kubeconfig" wait --for=condition=Ready nodes --all --timeout=120s
"$kind_bin" load docker-image "$image" --name "$cluster"
HYBRID_NET_LENS_TEST_IMAGE="$image" HYBRID_NET_LENS_TEST_KUBECONFIG="$kubeconfig" \
  go test -tags=integration -run TestKubernetesDeployment -v -timeout=10m ./integration