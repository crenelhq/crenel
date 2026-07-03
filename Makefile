# Crenel — build / test / release.
#
# Zero-dependency, fully-offline Go build. `make release` cross-compiles static
# binaries (including linux/arm64 for a Raspberry-Pi-class VPS). It does NOT
# publish anything — it only writes to ./dist.

BIN        := crenel
PKG        := ./cmd/crenel
DIST       := dist
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS    := -s -w -X main.version=$(VERSION)

# Release matrix: GOOS/GOARCH pairs. arm64 linux is the VPS target.
PLATFORMS  := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64

.PHONY: all build install test vet check race fmt clean release tidy

all: check build

build: ## Build the binary for the host platform into ./dist
	@mkdir -p $(DIST)
	CGO_ENABLED=0 go build -ldflags '$(LDFLAGS)' -o $(DIST)/$(BIN) $(PKG)
	@echo "built $(DIST)/$(BIN) ($(VERSION))"

install: ## go install the binary onto PATH
	go install -ldflags '$(LDFLAGS)' $(PKG)

test: ## Run the full test suite with the race detector
	go test -race ./...

vet:
	go vet ./...

# check is the green-bar gate every commit must pass.
check: ## go build + go vet + go test -race (the commit gate)
	go build ./...
	go vet ./...
	go test -race ./...

race: test

fmt:
	gofmt -l -w .

clean:
	rm -rf $(DIST)

tidy:
	go mod tidy

release: check ## Cross-compile static binaries for every platform into ./dist (does NOT publish)
	@mkdir -p $(DIST)
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		out=$(DIST)/$(BIN)-$(VERSION)-$$os-$$arch; \
		echo "building $$out"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -ldflags '$(LDFLAGS)' -o $$out $(PKG) || exit 1; \
	done
	@echo "release binaries in $(DIST)/ (not published)"
