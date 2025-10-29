SHELL := /bin/zsh

GO ?= go
OUT_DIR := bin

SERVER_PKG := ./server
CLIENT_PKG := ./client

SERVER_OUT := $(OUT_DIR)/dnsany-server
CLIENT_OUT := $(OUT_DIR)/dnsay

IMAGE ?= dnsay/server
TAG ?= latest

.PHONY: all release server client clean docker

all: server client

build: server client

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

server: $(OUT_DIR)
	$(GO) build -trimpath -ldflags "-s -w" -o $(SERVER_OUT) ./server

client: $(OUT_DIR)
	$(GO) build -trimpath -ldflags "-s -w" -o $(CLIENT_OUT) ./client

clean:
	rm -rf $(OUT_DIR)

docker:
	docker build -t $(IMAGE):$(TAG) -f Dockerfile .

