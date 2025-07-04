# Variables
BINARY_NAME=reflutter
BINARY_PATH=./bin/$(BINARY_NAME)
MAIN_PATH=./cmd/reflutter
VERSION=$(shell git describe --tags --always --dirty)
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME)"

# Default target
.PHONY: all
all: clean build

# Build the binary
.PHONY: build
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p bin
	@go build $(LDFLAGS) -o $(BINARY_PATH) .

# Build for multiple platforms
.PHONY: build-all
build-all:
	@echo "Building for multiple platforms..."
	@mkdir -p bin
	@GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-linux-amd64 .
	@GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-linux-arm64 .
	@GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-darwin-amd64 .
	@GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-darwin-arm64 .
	@GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-windows-amd64.exe .

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning..."
	@rm -rf bin/
	@go clean

# Run tests
.PHONY: test
test:
	@echo "Running tests..."
	@go test -v ./...

# Run tests with coverage
.PHONY: test-coverage
test-coverage:
	@echo "Running tests with coverage..."
	@go test -v -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html

# Install dependencies
.PHONY: deps
deps:
	@echo "Installing dependencies..."
	@go mod tidy
	@go mod download

# Format code
.PHONY: fmt
fmt:
	@echo "Formatting code..."
	@go fmt ./...

# Lint code
.PHONY: lint
lint:
	@echo "Linting code..."
	@golangci-lint run

# Install the binary
.PHONY: install
install: build
	@echo "Installing $(BINARY_NAME)..."
	@cp $(BINARY_PATH) /usr/local/bin/

# Create release
.PHONY: release
release: clean build-all
	@echo "Creating release..."
	@mkdir -p release
	@cp bin/* release/
	@tar -czf release/$(BINARY_NAME)-$(VERSION).tar.gz -C release .

# Development mode
.PHONY: dev
dev:
	@echo "Running in development mode..."
	@go run . --config=./config/dev.json

# Docker build
.PHONY: docker-build
docker-build:
	@echo "Building Docker image..."
	@docker build -t reflutter:latest .

# Docker run
.PHONY: docker-run
docker-run:
	@echo "Running Docker container..."
	@docker run -it --rm -v $(PWD):/workspace reflutter:latest

# Help
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  build         - Build the binary"
	@echo "  build-all     - Build for multiple platforms"
	@echo "  clean         - Clean build artifacts"
	@echo "  test          - Run tests"
	@echo "  test-coverage - Run tests with coverage"
	@echo "  deps          - Install dependencies"
	@echo "  fmt           - Format code"
	@echo "  lint          - Lint code"
	@echo "  install       - Install the binary"
	@echo "  release       - Create release"
	@echo "  dev           - Run in development mode"
	@echo "  docker-build  - Build Docker image"
	@echo "  docker-run    - Run Docker container"
	@echo "  help          - Show this help"
*/