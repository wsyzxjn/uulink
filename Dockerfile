# syntax=docker/dockerfile:1

# Build stage.
#
# The binary is pure Go (CGO disabled), so it is cross-compiled from the native
# build platform instead of emulating the target under QEMU. This keeps the
# multi-arch CI build fast.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build

WORKDIR /src

# Download modules first so the layer is reused whenever only sources change.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH
# Optional: bake a remote share configuration URL into the image so the
# container runs with zero arguments (README "Remote Configuration
# Distribution" mode).
ARG DEFAULT_CONFIG_URL=""
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" \
    go build -trimpath \
        -ldflags "-s -w -X main.DefaultConfigURL=${DEFAULT_CONFIG_URL}" \
        -o /out/uulink ./cmd/uulink

# Runtime stage.
FROM alpine:3.22

# ca-certificates: the UU Remote HTTPS API and TURN discovery need a trust store.
# tzdata: lets operators pin log timestamps with TZ=Asia/Shanghai.
RUN apk add --no-cache ca-certificates tzdata \
    && adduser -D -H -u 10001 uulink

COPY --from=build /out/uulink /usr/local/bin/uulink
COPY config.example.json /usr/local/share/uulink/config.example.json

# uulink resolves the default -config path relative to the working directory and
# rewrites that file after login or accountless device registration, so /data
# must stay writable by the runtime user.
RUN install -d -o uulink -g uulink /data
WORKDIR /data
USER uulink

# Defaults for local builds; CI overrides these with repository-derived values.
LABEL org.opencontainers.image.title="uulink" \
      org.opencontainers.image.description="Headless TCP port forwarding over the NetEase UU Remote P2P network" \
      org.opencontainers.image.source="https://github.com/wsyzxjn/uulink"

ENTRYPOINT ["/usr/local/bin/uulink"]
