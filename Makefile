BINARY_NAME=certman
BUILD_DIR=bin
VERSION?=1.0.0
COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)

# LDFLAGS injects variables into the binary at build time
LDFLAGS=-ldflags "-X main.Version=${VERSION} -X main.Commit=${COMMIT} -X main.BuildTime=${BUILD_TIME}"

.DEFAULT_GOAL := help

## run: compiles and runs the application locally
.PHONY: run
run:
	@go run certman


## tidy: cleans up and downloads go modules
.PHONY: tidy
tidy:
	@echo "Tidying go modules..."
	@go mod tidy


## fmt: Automatically formats go source files
.PHONY: fmt
fmt:
	@echo "Formatting code..."
	@go fmt ./...


## lint: lint runs golangci-lint analysis
.PHONY: lint
lint:
	@echo "Running linter..."
	@golangci-lint run ./...


## test: Runs all unit tests
.PHONY: test
test:
	@echo "Running tests..."
	@go test -v -race ./...


## test/cover: Runs tests and outputs a coverage report in HTML
.PHONY: test/cover
test/cover:
	@echo "Running tests with coverage..."
	@go test -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out


## build: Compiles the binary for the current system architecture
.PHONY: build
build: tidy fmt
	@echo "Building binary..."
	@mkdir -p $(BUILD_DIR)
	@go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) certman
	@echo "Build complete: $(BUILD_DIR)/$(BINARY_NAME)"


## build/cross: Cross-compiles the binary for Linux, Windows, macOS and freebsd
.PHONY: build/cross
build/cross: tidy fmt
	@echo "=> Cross-compiling for multiple platforms..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 certman
	GOOS=linux GOARCH=arm go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm certman
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe certman
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 certman


## clean: Removes the build directory and test artifacts
.PHONY: clean
clean:
	@echo "=> Cleaning build directory..."
	@rm -rf $(BUILD_DIR)
	@rm -f coverage.out
	@go clean


## help: Shows this help menu with target descriptions
.PHONY: help
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -F -h "##" $(MAKEFILE_LIST) | grep -F -v fgrep | sed -e 's/\\$$//' | sed -e 's/## //' | awk -F: '{printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
