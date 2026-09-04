# syntax=docker/dockerfile:1

FROM golang:1.26-alpine AS builder
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/cleargate ./cmd/server

FROM alpine:3.21
RUN apk add --no-cache ca-certificates wget && adduser -D -u 10001 cleargate
USER cleargate
WORKDIR /app
COPY --from=builder /out/cleargate .
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=40s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
CMD ["./cleargate"]
