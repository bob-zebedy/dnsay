FROM golang:1.25.3-alpine AS builder
WORKDIR /app

ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY server ./server

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath -ldflags "-s -w" -o /out/dnsany-server ./server

FROM scratch AS runtime
WORKDIR /
COPY --from=builder /out/dnsany-server /dnsany-server

EXPOSE 5335/tcp 5335/udp

ENTRYPOINT ["/dnsany-server"]
CMD ["--bind","0.0.0.0","--port","5335"]