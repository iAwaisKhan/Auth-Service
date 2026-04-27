.PHONY: help build run dev test test-coverage lint fmt tidy docker-up docker-down docker-build \
        migrate-up swagger clean

# ── Variables ─────────────────────────────────────────────────────────────────
APP_NAME   := auth-service
CMD_PATH   := ./cmd/server
BIN_DIR    := ./bin
BIN        := $(BIN_DIR)/$(APP_NAME)
GO         := go
GOFLAGS    := -ldflags="-w -s"
DOCKER_IMG := $(APP_NAME):latest

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ── Build ─────────────────────────────────────────────────────────────────────
build: ## Build the binary
	@mkdir -p $(BIN_DIR)
	$(GO) build $(GOFLAGS) -o $(BIN) $(CMD_PATH)
	@echo "✅  Built $(BIN)"

run: build ## Build and run the server
	$(BIN)

dev: ## Run with live reload (requires air: go install github.com/cosmtrek/air@latest)
	air -c .air.toml

# ── Test ──────────────────────────────────────────────────────────────────────
test: ## Run all unit tests
	$(GO) test ./... -v -count=1

test-coverage: ## Run tests with coverage report
	$(GO) test ./... -coverprofile=coverage.out -covermode=atomic
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "📊  Coverage report: coverage.html"

test-race: ## Run tests with race detector
	$(GO) test -race ./... -count=1

# ── Quality ───────────────────────────────────────────────────────────────────
lint: ## Run golangci-lint (requires golangci-lint)
	golangci-lint run ./...

fmt: ## Format code
	$(GO) fmt ./...
	goimports -w . 2>/dev/null || true

tidy: ## Tidy and verify go modules
	$(GO) mod tidy
	$(GO) mod verify

vet: ## Run go vet
	$(GO) vet ./...

# ── Docker ────────────────────────────────────────────────────────────────────
docker-build: ## Build Docker image
	docker build -t $(DOCKER_IMG) .

docker-up: ## Start all services (app + postgres + redis)
	docker compose up -d
	@echo "🚀  Services started. API: http://localhost:8080"

docker-down: ## Stop all services
	docker compose down

docker-logs: ## Tail application logs
	docker compose logs -f app

docker-clean: ## Stop services and remove volumes
	docker compose down -v --remove-orphans

# ── Database ──────────────────────────────────────────────────────────────────
db-shell: ## Open a psql shell
	docker compose exec postgres psql -U $${DB_USER:-postgres} -d $${DB_NAME:-authdb}

redis-cli: ## Open a redis-cli shell
	docker compose exec redis redis-cli

# ── Swagger ───────────────────────────────────────────────────────────────────
swagger: ## Generate Swagger docs (requires swag: go install github.com/swaggo/swag/cmd/swag@latest)
	swag init -g cmd/server/main.go -o ./docs --parseDependency --parseInternal
	@echo "📖  Swagger docs at http://localhost:8080/swagger/index.html"

# ── Setup ─────────────────────────────────────────────────────────────────────
setup: ## First-time project setup
	@cp -n .env.example .env || true
	$(GO) mod download
	@echo "✅  Setup complete. Edit .env and run: make docker-up"

clean: ## Remove build artifacts
	rm -rf $(BIN_DIR) coverage.out coverage.html
