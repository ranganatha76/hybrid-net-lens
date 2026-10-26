FROM golang:1.26.10-bookworm@sha256:632dff7351799a5a9954a48dc06670ade72ee44e8c351cdc0e5a57af2fea21af AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/hybrid-net-lens ./cmd/hybrid-net-lens

FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8 AS runtime
RUN apt-get update \
	&& DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates iperf3 iputils-ping libcap2-bin \
	&& setcap -r /usr/bin/ping \
	&& chmod u-s /usr/bin/ping \
	&& rm -rf /var/lib/apt/lists/* \
	&& install -d -m 0700 -o 10001 -g 10001 /data \
	&& install -d -m 0755 /etc/hybrid-net-lens
COPY --from=build /out/hybrid-net-lens /hybrid-net-lens
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/hybrid-net-lens"]
CMD ["serve", "-config", "/etc/hybrid-net-lens/config.json"]