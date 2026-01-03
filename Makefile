.PHONY: help build test test-coverage run clean install lint fmt vet

# Variables
BINARY_NAME=gohoarder
BINARY_PATH=bin/$(BINARY_NAME)
CMD_PATH=./cmd/gohoarder
# Generate semantic version using script, fallback to 'dev' if script fails
VERSION?=$(shell ./script/generate-version.sh 2>/dev/null || echo "dev")
GIT_COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS=-ldflags "-X github.com/lukaszraczylo/gohoarder/internal/version.Version=$(VERSION) \
                   -X github.com/lukaszraczylo/gohoarder/internal/version.GitCommit=$(GIT_COMMIT) \
                   -X github.com/lukaszraczylo/gohoarder/internal/version.BuildTime=$(BUILD_TIME)"

help: ## Display this help screen
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build the binary
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p bin
	@go build -buildvcs=false $(LDFLAGS) -o $(BINARY_PATH) $(CMD_PATH)
	@echo "Binary built: $(BINARY_PATH)"

build-all: ## Build for all platforms
	@echo "Building for all platforms..."
	@mkdir -p bin
	GOOS=linux GOARCH=amd64 go build -buildvcs=false $(LDFLAGS) -o bin/$(BINARY_NAME)-linux-amd64 $(CMD_PATH)
	GOOS=linux GOARCH=arm64 go build -buildvcs=false $(LDFLAGS) -o bin/$(BINARY_NAME)-linux-arm64 $(CMD_PATH)
	GOOS=darwin GOARCH=amd64 go build -buildvcs=false $(LDFLAGS) -o bin/$(BINARY_NAME)-darwin-amd64 $(CMD_PATH)
	GOOS=darwin GOARCH=arm64 go build -buildvcs=false $(LDFLAGS) -o bin/$(BINARY_NAME)-darwin-arm64 $(CMD_PATH)
	@echo "All binaries built"

test: ## Run tests
	@echo "Running tests..."
	@go test -v ./...

test-coverage: ## Run tests with coverage
	@echo "Running tests with coverage..."
	@go test -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

test-race: ## Run tests with race detector
	@echo "Running tests with race detector..."
	@go test -race ./...

bench: ## Run benchmarks
	@echo "Running benchmarks..."
	@go test -bench=. -benchmem ./...

run: build ## Build and run both backend and frontend for development
	@echo "Starting $(BINARY_NAME) and frontend in development mode..."
	@echo ""
	@echo "Backend will run on: http://localhost:8080 (configured in config.yaml)"
	@echo "Frontend will run on: http://localhost:5173 (configured in frontend/.env)"
	@echo ""
	@echo "To change ports:"
	@echo "  - Backend: Edit 'server.port' in config.yaml"
	@echo "  - Frontend: Edit 'VITE_PORT' and 'VITE_BACKEND_URL' in frontend/.env"
	@echo ""
	@trap 'kill 0' SIGINT; \
	$(BINARY_PATH) serve & \
	cd frontend && pnpm dev & \
	wait

run-backend: build ## Build and run only the backend server
	@echo "Starting $(BINARY_NAME)..."
	@$(BINARY_PATH) serve

run-dev: ## Run with example config
	@echo "Starting $(BINARY_NAME) in development mode..."
	@go run $(CMD_PATH) serve --config config.yaml.example

clean: ## Clean build artifacts
	@echo "Cleaning..."
	@rm -rf bin/
	@rm -f coverage.out coverage.html
	@rm -f *.db *.db-shm *.db-wal
	@echo "Clean complete"

clean-db: ## Clean all local cache and database files (requires confirmation)
	@echo "WARNING: This will delete all cached packages and scan results!"
	@echo "Paths to be cleaned:"
	@echo "  - ./data/storage (package cache)"
	@echo "  - ./data/gohoarder.db and gohoarder.db (metadata database)"
	@echo "  - /tmp/trivy (Trivy cache)"
	@echo ""
	@printf "Are you sure you want to continue? [y/N] " && read confirm && [ "$$confirm" = "y" ] || (echo "Cancelled." && exit 1)
	@echo "Cleaning database and cache..."
	@rm -rf ./data/storage ./data
	@rm -f gohoarder.db gohoarder.db-shm gohoarder.db-wal
	@rm -rf /tmp/trivy
	@echo "Database and cache cleaned successfully"

clean-db-force: ## Clean all local cache and database files (no confirmation)
	@echo "Cleaning database and cache..."
	@rm -rf ./data/storage ./data
	@rm -f gohoarder.db gohoarder.db-shm gohoarder.db-wal
	@rm -rf /tmp/trivy
	@echo "Database and cache cleaned successfully"

install: build ## Install the binary
	@echo "Installing $(BINARY_NAME)..."
	@cp $(BINARY_PATH) $(GOPATH)/bin/
	@echo "Installed to $(GOPATH)/bin/$(BINARY_NAME)"

lint: ## Run linters
	@echo "Running linters..."
	@go vet ./...
	@which golangci-lint > /dev/null || (echo "golangci-lint not installed" && exit 1)
	@golangci-lint run

fmt: ## Format code
	@echo "Formatting code..."
	@gofmt -s -w .
	@which goimports > /dev/null && goimports -w . || true

vet: ## Run go vet
	@go vet ./...

tidy: ## Tidy dependencies
	@go mod tidy

docker-build: ## Build Docker image
	@echo "Building Docker image..."
	@docker build -t $(BINARY_NAME):$(VERSION) .

docker-run: docker-build ## Run Docker container
	@echo "Running Docker container..."
	@docker run -p 8080:8080 $(BINARY_NAME):$(VERSION)

test-packages: ## Download test packages through gohoarder proxy (clean + vulnerable packages)
	@echo "Reading backend port from config.yaml..."
	@PORT=$$(grep "^  port:" config.yaml | awk '{print $$2}'); \
	if [ -z "$$PORT" ]; then PORT=8080; fi; \
	export GOHOARDER_URL="http://localhost:$$PORT"; \
	./script/test-packages.sh

.DEFAULT_GOAL := help
