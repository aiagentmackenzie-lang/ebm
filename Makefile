.PHONY: all build build-linux build-windows build-darwin test clean install

BINARY=ebm
VERSION=1.0.0
LDFLAGS=-ldflags "-s -w -X main.Version=$(VERSION)"

all: build

build-linux:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build $(LDFLAGS) -o dist/ebm-linux-amd64 ./cmd/ebm

build-windows:
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build $(LDFLAGS) -o dist/ebm-windows-amd64.exe ./cmd/ebm

build-darwin:
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build $(LDFLAGS) -o dist/ebm-darwin-arm64 ./cmd/ebm

build: build-linux build-windows build-darwin

test:
	go test ./...

clean:
	rm -rf dist/

install: build
	@echo "Run ./scripts/install.sh (Linux/macOS) or ./scripts/install.ps1 (Windows)"

.DEFAULT_GOAL := build
