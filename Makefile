# Tiger2Go Developer Makefile

.PHONY: all build run test clean lint sec audit trivy tools tools-clean fmt coverage help

# Default target
all: lint audit test build

# Application
BINARY_NAME=tigerfetch
ENTRY_POINT=./cmd/tigerfetch

# ----------------------------------------------------------------------------
# Tooling (repo-local installs)
# ----------------------------------------------------------------------------
BIN_DIR ?= $(CURDIR)/bin
GOBIN ?= $(abspath $(BIN_DIR))

GOLANGCI_LINT_VERSION ?= v2.8.0
GOVULNCHECK_VERSION ?= v1.1.4
GOSEC_VERSION ?= v2.22.11

GOLANGCI_LINT := $(BIN_DIR)/golangci-lint
GOVULNCHECK := $(BIN_DIR)/govulncheck
GOSEC := $(BIN_DIR)/gosec

tools: $(GOLANGCI_LINT) $(GOVULNCHECK) $(GOSEC) ## Install/refresh local tooling into ./bin

tools-clean: ## Remove locally installed tooling (./bin)
	rm -rf $(BIN_DIR)

$(GOLANGCI_LINT):
	@mkdir -p $(BIN_DIR)
	GOBIN="$(GOBIN)" go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

$(GOVULNCHECK):
	@mkdir -p $(BIN_DIR)
	GOBIN="$(GOBIN)" go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

$(GOSEC):
	@mkdir -p $(BIN_DIR)
	GOBIN="$(GOBIN)" go install github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION)

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


lint: $(GOLANGCI_LINT) ## Run linter
	$(GOLANGCI_LINT) run

fmt: ## Format code
	go fmt ./...

# -----------------------------------------------------------------------------
# Security (DevSecOps)
# -----------------------------------------------------------------------------

audit: $(GOVULNCHECK) build ## Run Go native vulnerability check (SCA)
	$(GOVULNCHECK) -mode=binary ./$(BINARY_NAME)


sec: $(GOSEC) ## Run Golang Security Checker (SAST)
	$(GOSEC) ./...

trivy: ## Build image and scan with Trivy
	docker build -t tiger2go:local .
	trivy image tiger2go:local

# -----------------------------------------------------------------------------
# Help
# -----------------------------------------------------------------------------
help: ## Display this help screen
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'
