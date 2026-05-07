FROM --platform=$BUILDPLATFORM golang:1.25.3-alpine AS builder
ARG TARGETOS=linux
ARG TARGETARCH=amd64
WORKDIR /app

ENV CGO_ENABLED=0

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY shared ./shared
COPY server ./server

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags "-s -w" -o /out/dnsay-server ./server

FROM scratch AS runtime
WORKDIR /
COPY --from=builder /out/dnsay-server /dnsay-server

EXPOSE 5335/tcp 5335/udp

ENTRYPOINT ["/dnsay-server"]
CMD ["--bind","0.0.0.0","--port","5335","--verbose"]
