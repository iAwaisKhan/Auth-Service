# 🔐 Auth Microservice

A production-ready Authentication Microservice built in Go with clean architecture, JWT authentication, OAuth 2.0 integration (Google & GitHub), RBAC, and Redis-backed refresh token rotation.

---

## 📁 Project Structure

```
auth-service/
├── cmd/
│   └── server/
│       └── main.go              # Entry point, graceful shutdown
├── internal/
│   ├── auth/
│   │   ├── handler/
│   │   │   └── auth_handler.go  # HTTP handlers (Gin)
│   │   ├── repository/
│   │   │   └── auth_repository.go # DB access layer (GORM)
│   │   └── service/
│   │       ├── auth_service.go     # Business logic
│   │       ├── auth_service_test.go
│   │       ├── oauth_service.go    # Google & GitHub OAuth
│   │       └── token_service.go    # JWT generation & validation
│   └── middleware/
│       ├── jwt.go               # JWT auth middleware
│       ├── rate_limit.go        # Redis-backed rate limiting
│       ├── cors.go              # CORS configuration
│       └── logger.go            # Request logging + recovery
├── pkg/
│   ├── cache/
│   │   └── redis.go             # Redis client wrapper
│   ├── config/
│   │   └── config.go            # Config via env vars / .env
│   ├── database/
│   │   ├── database.go          # GORM + PostgreSQL setup
│   │   └── models.go            # User & OAuthAccount models
│   ├── errors/
│   │   └── errors.go            # Centralized AppError type
│   ├── logger/
│   │   └── logger.go            # Zap structured logger
│   └── validator/
│       ├── validator.go
│       └── validator_test.go
├── routes/
│   └── routes.go                # Route registration & DI wiring
├── .air.toml                    # Live-reload config
├── .env.example                 # Environment variable template
├── .gitignore
├── Dockerfile                   # Multi-stage production build
├── docker-compose.yml           # App + Postgres + Redis
├── go.mod
├── Makefile
└── README.md
```

---

## 🚀 Quick Start

### Prerequisites

- [Go 1.21+](https://golang.org/dl/)
- [Docker & Docker Compose](https://docs.docker.com/get-docker/)
- [Make](https://www.gnu.org/software/make/)

### 1. Clone and configure

```bash
git clone https://github.com/yourorg/auth-service.git
cd auth-service
cp .env.example .env
```

Edit `.env` — at minimum, set these values:

```bash
JWT_ACCESS_SECRET=$(openssl rand -base64 64)
JWT_REFRESH_SECRET=$(openssl rand -base64 64)
DB_PASSWORD=your_secure_db_password
```

### 2. Run with Docker Compose (recommended)

```bash
make docker-up
```

This starts PostgreSQL, Redis, and the application. The API is available at `http://localhost:8080`.

### 3. Run locally (without Docker app container)

```bash
# Start only infrastructure
docker compose up -d postgres redis

# Download dependencies
go mod download

# Run the server
make run
```

---

## 📡 API Reference

### Base URL

```
http://localhost:8080/api/v1
```

### Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/health` | — | Health check |
| `POST` | `/signup` | — | Register with email + password |
| `POST` | `/login` | — | Login with email + password |
| `POST` | `/refresh` | — | Rotate refresh token → new token pair |
| `POST` | `/logout` | — | Revoke refresh token |
| `GET` | `/oauth/google` | — | Initiate Google OAuth |
| `GET` | `/oauth/google/callback` | — | Google OAuth callback |
| `GET` | `/oauth/github` | — | Initiate GitHub OAuth |
| `GET` | `/oauth/github/callback` | — | GitHub OAuth callback |
| `GET` | `/profile` | JWT | Get current user profile |
| `GET` | `/admin` | JWT + admin role | Admin dashboard |

### Example: Signup

```bash
curl -X POST http://localhost:8080/api/v1/signup \
  -H "Content-Type: application/json" \
  -d '{"name":"Alice","email":"alice@example.com","password":"Password1"}'
```

**Response:**

```json
{
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "alice@example.com",
    "name": "Alice",
    "role": "user",
    "provider": "local"
  },
  "tokens": {
    "access_token": "eyJ...",
    "refresh_token": "eyJ...",
    "expires_in": 900
  }
}
```

### Example: Authenticated request

```bash
curl http://localhost:8080/api/v1/profile \
  -H "Authorization: Bearer <access_token>"
```

### Example: Token refresh

```bash
curl -X POST http://localhost:8080/api/v1/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"<refresh_token>"}'
```

---

## 🔐 Security Architecture

### JWT Token Flow

```
Client                     Server                    Redis
  │                           │                        │
  ├─── POST /login ──────────►│                        │
  │                           ├── hash compare         │
  │                           ├── generate access JWT  │
  │                           ├── generate refresh JWT │
  │                           ├── store refresh JTI ──►│
  │◄── {access, refresh} ─────┤                        │
  │                           │                        │
  ├─── GET /profile ─────────►│                        │
  │    Authorization: Bearer  │                        │
  │                           ├── validate access JWT  │
  │◄── user profile ──────────┤                        │
  │                           │                        │
  ├─── POST /refresh ────────►│                        │
  │    {refresh_token}        ├── validate refresh JWT │
  │                           ├── check JTI in Redis ─►│
  │                           ├── delete old JTI ─────►│
  │                           ├── issue new pair       │
  │                           ├── store new JTI ──────►│
  │◄── {new_access, new_ref} ─┤                        │
```

### Token Rotation Strategy

Every call to `/refresh` **invalidates** the old refresh token and issues a completely new pair. This means:
- Stolen refresh tokens are single-use
- Reuse of a revoked token returns `401 Unauthorized`

### Password Hashing

bcrypt with `DefaultCost` (12 rounds).

### Rate Limiting

| Route Group | Limit |
|-------------|-------|
| `/signup`, `/login`, `/refresh`, `/logout`, `/oauth/*` | 10 req/min per IP |
| `/profile`, `/admin` | 100 req/min per IP |

Backed by Redis for correctness across multiple replicas.

---

## 🧱 Clean Architecture Layers

```
Handler  →  receives HTTP, validates input, calls Service
Service  →  business logic, orchestrates calls to Repository and TokenService
Repository → pure DB access via GORM, no business logic
```

Dependencies point inward: Handler knows Service, Service knows Repository. Repository knows nothing about the layers above it.

---

## 🗄️ Database Schema

### users

| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID | Primary key |
| `email` | VARCHAR(255) | Unique, not null |
| `password` | VARCHAR(255) | bcrypt hash; empty for OAuth users |
| `provider` | VARCHAR(50) | `local`, `google`, `github` |
| `role` | VARCHAR(50) | `user`, `admin` |
| `name` | VARCHAR(255) | Display name |
| `avatar_url` | VARCHAR(512) | Profile picture |
| `is_active` | BOOLEAN | Soft-disable accounts |
| `created_at` | TIMESTAMPTZ | |
| `updated_at` | TIMESTAMPTZ | |
| `deleted_at` | TIMESTAMPTZ | Soft delete |

### oauth_accounts

| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID | Primary key |
| `user_id` | UUID | FK → users |
| `provider` | VARCHAR(50) | `google`, `github` |
| `provider_user_id` | VARCHAR(255) | Provider's user ID |
| `access_token` | TEXT | Encrypted in transit |
| `refresh_token` | TEXT | |
| `expires_at` | TIMESTAMPTZ | |

---

## 🧪 Testing

```bash
# Run all tests
make test

# With race detection
make test-race

# With coverage HTML report
make test-coverage
```

The test suite uses an **in-memory fake repository** — no database required.

---

## ⚙️ Configuration Reference

All configuration is via environment variables (or `.env`).

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_PORT` | `8080` | HTTP port |
| `APP_ENV` | `development` | `development` or `production` |
| `APP_BASE_URL` | `http://localhost:8080` | Public base URL |
| `DB_HOST` | `localhost` | PostgreSQL host |
| `DB_PORT` | `5432` | PostgreSQL port |
| `DB_USER` | `postgres` | Database user |
| `DB_PASSWORD` | — | **Required** |
| `DB_NAME` | `authdb` | Database name |
| `DB_SSLMODE` | `disable` | SSL mode (`verify-full` in prod) |
| `REDIS_HOST` | `localhost` | Redis host |
| `REDIS_PORT` | `6379` | Redis port |
| `REDIS_PASSWORD` | — | Redis password |
| `JWT_ACCESS_SECRET` | — | **Required** — min 32 chars |
| `JWT_REFRESH_SECRET` | — | **Required** — different from access |
| `JWT_ACCESS_EXPIRY` | `15m` | Access token lifetime |
| `JWT_REFRESH_EXPIRY` | `168h` | Refresh token lifetime |
| `GOOGLE_CLIENT_ID` | — | OAuth app credential |
| `GOOGLE_CLIENT_SECRET` | — | OAuth app credential |
| `GITHUB_CLIENT_ID` | — | OAuth app credential |
| `GITHUB_CLIENT_SECRET` | — | OAuth app credential |

---

## 🔧 OAuth Setup

### Google

1. Go to [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
2. Create an **OAuth 2.0 Client ID** (Web application)
3. Add Authorized redirect URI: `http://localhost:8080/api/v1/oauth/google/callback`
4. Copy `Client ID` and `Client Secret` to `.env`

### GitHub

1. Go to [GitHub Developer Settings](https://github.com/settings/applications/new)
2. Set Homepage URL: `http://localhost:8080`
3. Set Callback URL: `http://localhost:8080/api/v1/oauth/github/callback`
4. Copy `Client ID` and generate a `Client Secret`, paste into `.env`

---

## 🏭 Production Checklist

- [ ] Set `APP_ENV=production`
- [ ] Use strong random secrets for `JWT_ACCESS_SECRET` and `JWT_REFRESH_SECRET`
- [ ] Set `DB_SSLMODE=verify-full` with proper certificates
- [ ] Set a `REDIS_PASSWORD`
- [ ] Put the service behind a TLS-terminating reverse proxy (nginx / Caddy)
- [ ] Restrict CORS `AllowOrigins` in `middleware/cors.go`
- [ ] Set up log aggregation (Datadog, Loki, etc.)
- [ ] Set up health-check monitoring on `/health`

---

## 📦 Makefile Commands

```
make help          Show all commands
make build         Build binary
make run           Build and run
make dev           Live reload with Air
make test          Run tests
make test-coverage Generate coverage report
make lint          Run golangci-lint
make fmt           Format code
make docker-up     Start all Docker services
make docker-down   Stop Docker services
make swagger       Generate Swagger docs
make setup         First-time project setup
```

---

## 📄 License

MIT
