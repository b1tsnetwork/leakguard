# syntax=docker/dockerfile:1

# --- Build ---
FROM golang:1.24-alpine AS build
RUN apk add --no-cache build-base
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG VERSION=dev
# SQLite-Treiber benötigt CGO; statisch gegen musl gelinkt
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=1 go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION} -linkmode external -extldflags '-static'" \
      -tags "sqlite_omit_load_extension osusergo netgo" \
      -o /out/leakguard ./cmd/leakguard

# --- Runtime ---
FROM alpine:3.24
RUN apk add --no-cache ca-certificates tzdata \
 && adduser -D -H -u 10001 leakguard \
 && mkdir -p /data && chown leakguard:leakguard /data
# Alles Persistente liegt unter /data: config.yaml, leakguard.db (+ -wal/-shm), optionale CA-/Sperrlisten-Dateien.
# Fehlt /data/config.yaml, wird beim ersten Start eine Vorlage mit zufälligem secret angelegt.
ENV TZ=Europe/Berlin \
    LEAKGUARD_CONFIG=/data/config.yaml
COPY --from=build /out/leakguard /usr/local/bin/leakguard
USER leakguard
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/leakguard"]

LABEL org.opencontainers.image.title="LeakGuard" \
      org.opencontainers.image.description="Abarbeitung von SOC-Meldungen zu geleakten Kennwörtern"
