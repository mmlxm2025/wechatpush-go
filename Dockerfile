# syntax=docker/dockerfile:1

FROM golang:1.27.3-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go version && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/qywx-push ./cmd/server

FROM alpine:3.24

ARG VCS_REF=release
ARG APP_VERSION=2.0.0

RUN apk add --no-cache ca-certificates tzdata wget su-exec \
    && addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

COPY --from=builder /out/qywx-push /app/qywx-push
COPY --from=builder /src/public /app/public

RUN mkdir -p /app/database /app/logs && chown -R appuser:appgroup /app

ENV NODE_ENV=production \
    PORT=12121 \
    DB_PATH=/app/database/notifier.db \
    APP_REVISION=${VCS_REF} \
    APP_VERSION=${APP_VERSION} \
    TZ=Asia/Shanghai

EXPOSE 12121

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:12121/health/ready || exit 1

ENTRYPOINT ["sh", "-c", "mkdir -p /app/database /app/logs && chown -R appuser:appgroup /app/database /app/logs && exec su-exec appuser:appgroup /app/qywx-push"]
