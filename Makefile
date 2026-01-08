# Tiger2Go Developer Makefile

.PHONY: all build run test clean lint sec audit help

# Default target
all: lint audit test build

# Application
BINARY_NAME=tigerfetch
ENTRY_POINT=./cmd/tigerfetch

# -----------------------------------------------------------------------------
# Development
# -----------------------------------------------------------------------------
build: ## Build the binary
	@echo "Building $(BINARY_NAME)..."
	go build -o $(BINARY_NAME) $(ENTRY_POINT)

run: ## Run the application locally
	go run $(ENTRY_POINT)

clean: ## Clean build artifacts
	go clean
	rm -f $(BINARY_NAME)

# -----------------------------------------------------------------------------
# Quality & Testing
# -----------------------------------------------------------------------------
test: ## Run unit tests with race detection
	go test -v -race ./...

coverage: ## Run tests and generate coverage report
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out

lint: ## Run linter (requires golangci-lint installed)
	golangci-lint run

fmt: ## Format code
	go fmt ./...

# -----------------------------------------------------------------------------
# Security (DevSecOps)
# -----------------------------------------------------------------------------
audit: ## Run Go native vulnerability check (SCA)
	govulncheck ./...

sec: ## Run Golang Security Checker (SAST)
	gosec ./...

trivy: ## Build image and scan with Trivy
	docker build -t tiger2go:local .
	trivy image tiger2go:local

# -----------------------------------------------------------------------------
# Help
# -----------------------------------------------------------------------------
help: ## Display this help screen
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'
