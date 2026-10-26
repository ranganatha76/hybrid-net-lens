.PHONY: build test vet fmt check clean security image image-security integration cluster-check

VERSION ?= dev
IMAGE ?= hybrid-net-lens:verify
TRIVY_IMAGE ?= aquasec/trivy@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o bin/hybrid-net-lens ./cmd/hybrid-net-lens

test:
	go test -race -count=1 ./...

vet:
	go vet ./...

fmt:
	gofmt -w cmd internal integration

check: vet test
	test -z "$$(gofmt -l cmd internal integration)"

security:
	go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...

image:
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE) .

image-security:
	docker run --rm --mount type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock,readonly $(TRIVY_IMAGE) image --no-progress --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 $(IMAGE)

integration:
	HYBRID_NET_LENS_TEST_IMAGE=$(IMAGE) go test -tags=integration -run TestContainerEndToEnd -count=1 -v -timeout=5m ./integration

cluster-check:
	HYBRID_NET_LENS_TEST_IMAGE=$(IMAGE) bash scripts/verify-cluster.sh

clean:
	rm -f bin/hybrid-net-lens coverage.out coverage.html