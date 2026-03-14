# ForgeAI Connector Host — Dockerfile
# Multi-stage build for minimal runtime image

FROM golang:1.22-alpine AS builder

WORKDIR /build
COPY go.mod ./
COPY *.go ./

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o connector-agent .

# ── Runtime ──
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /build/connector-agent /usr/local/bin/connector-agent

LABEL org.opencontainers.image.source="https://github.com/kravitzai/forge-flow-friend"
LABEL org.opencontainers.image.description="ForgeAI Connector Host — Multi-Target Agent"

# Non-root user
RUN adduser -D -u 1000 forgeai
RUN mkdir -p /etc/forgeai/secrets && chown -R forgeai:forgeai /etc/forgeai

# Config volume
VOLUME /etc/forgeai

USER forgeai

ENTRYPOINT ["connector-agent"]
