.PHONY: all build test test-verbose test-coverage lint fmt clean help

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOFMT=gofmt
GOLINT=golangci-lint
GOMOD=$(GOCMD) mod
GOCLEAN=$(GOCMD) clean

# Build info
BINARY_NAME=go-cxf
COVERAGE_FILE=coverage.out

# Default target
all: fmt lint test

## build: Build the library (compile check)
build:
	$(GOBUILD) -v ./...

## test: Run all tests
test:
	$(GOTEST) -v ./...

## test-short: Run tests without verbose output
test-short:
	$(GOTEST) ./...

## test-race: Run tests with race detector
test-race:
	$(GOTEST) -race -v ./...

## test-coverage: Run tests with coverage report
test-coverage:
	$(GOTEST) -coverprofile=$(COVERAGE_FILE) -covermode=atomic ./...
	$(GOCMD) tool cover -func=$(COVERAGE_FILE)

## test-coverage-html: Generate HTML coverage report
test-coverage-html: test-coverage
	$(GOCMD) tool cover -html=$(COVERAGE_FILE) -o coverage.html
	@echo "Coverage report generated: coverage.html"

## lint: Run golangci-lint
lint:
	$(GOLINT) run ./...

## fmt: Format code
fmt:
	$(GOFMT) -w .

## fmt-check: Check if code is formatted (for CI)
fmt-check:
	@fmt_out=$$($(GOFMT) -l .); \
	if [ -n "$$fmt_out" ]; then \
		echo "The following files are not gofmt formatted:"; \
		echo "$$fmt_out"; \
		exit 1; \
	fi

## tidy: Tidy go.mod
tidy:
	$(GOMOD) tidy

## verify: Verify dependencies
verify:
	$(GOMOD) verify

## download: Download dependencies
download:
	$(GOMOD) download

## clean: Clean build artifacts
clean:
	$(GOCLEAN)
	rm -f $(COVERAGE_FILE) coverage.html

## ci: Run all CI checks (format, lint, test)
ci: fmt-check lint test-short

## help: Show this help
help:
	@echo "Available targets:"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed 's/^/ /'
