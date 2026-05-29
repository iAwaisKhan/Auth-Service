# Auth Service

> Production-ready authentication microservice in Go — JWT, OAuth2, RBAC, Redis-backed token rotation, rate limiting.

---

### What is this?

A backend authentication service built from scratch using Go, PostgreSQL, and Redis.

The service supports local authentication, Google and GitHub OAuth login, JWT-based authorization, session management, and role-based access control. It was built to explore how modern authentication systems work internally and to implement the core building blocks commonly used in production backend applications.

The project focuses on clean architecture, security, scalability, and maintainability while keeping full control over the authentication and authorization workflow.


---

## High Level Architecture

<img width="1536" height="1024" alt="Architecture auth" src="https://github.com/user-attachments/assets/b3df06bb-ae07-4e08-8956-5ae1ae1dc815" />

## Workflow

<img width="1536" height="1024" alt="workflow auth" src="https://github.com/user-attachments/assets/cda8dd32-261d-4268-9f11-64b07cc4e7ac" />

### Screenshot

<table>
<tr>
<th>Auth Service Startup Logs</th>
<th>Redis Container Status</th>
</tr>

<tr>
<td>
<img src="https://github.com/user-attachments/assets/3fc7a105-4138-440d-b109-f234db9af47b">
</td>

<td>
<img src="https://github.com/user-attachments/assets/f7eb1c60-6a9e-4ea6-99a9-12ca8cc1736f">
</td>
</tr>
</table>

### Result

- Auth Service started successfully on port `8080`.
- All authentication and authorization routes were registered successfully.
- Health check endpoint responded with HTTP `200 OK`.
- Structured request logging middleware is functioning correctly.
- Redis container started successfully and is accessible.
- Session management infrastructure initialized successfully.
- JWT authentication components loaded successfully.
- OAuth endpoints for Google and GitHub registered successfully.
- Application dependencies connected and verified.
- Service is ready to handle authentication, authorization, and session management requests.


### Layer Responsibilities

Handler      → HTTP requests, validation, JSON responses  
Middleware   → JWT, RBAC, rate limiting, logging  
Service      → Business logic and workflow orchestration  
Repository   → PostgreSQL operations via GORM  
TokenService → JWT generation, validation, refresh lifecycle  
OAuthService → Google/GitHub authentication flow  
Redis        → Sessions, refresh tokens, token blacklist

### Dependency Flow

```text
Router
  ↓
Handler
  ↓
Service
 ├── Repository (PostgreSQL)
 ├── TokenService (JWT)
 ├── OAuthService
 └── Redis

Service must not depend on Handler.

Repository must not contain business logic.

Handler must not directly access Database.

JWT operations must go through TokenService.

Database access must go through Repository.
```


Dependencies point inward only.

---

## Components

| Component | Role |
|---|---|
| **Postgres** | Users, OAuth accounts, soft deletes |
| **Redis** | Refresh token JTI store, IP-based rate limiter |
| **Auth Handler** | HTTP layer — validation, routing, response shaping |
| **Auth Service** | Signup, login, lockout, OAuth account linking |
| **Token Service** | Access + refresh JWT generation, rotation, revocation |
| **OAuth Service** | Google & GitHub provider flows |

---

## Project Structure

```
auth-service/
├── cmd/server/main.go              # Entry point, graceful shutdown
├── internal/
│   ├── auth/
│   │   ├── handler/auth_handler.go # HTTP layer (Gin)
│   │   ├── repository/             # DB access (GORM)
│   │   └── service/
│   │       ├── auth_service.go     # Core business logic
│   │       ├── token_service.go    # JWT + Redis lifecycle
│   │       └── oauth_service.go    # Google & GitHub flows
│   └── middleware/
│       ├── jwt.go                  # JWT auth middleware
│       ├── rate_limit.go           # Redis-backed rate limiter
│       ├── cors.go
│       └── logger.go               # Zap request logger + recovery
├── pkg/
│   ├── cache/redis.go
│   ├── config/config.go            # Env-var config loader
│   ├── crypto/token_cipher.go      # AES-256-GCM token encryption
│   ├── database/
│   │   ├── database.go             # GORM + Postgres + auto-migrate
│   │   └── models.go               # User & OAuthAccount models
│   ├── errors/errors.go            # Typed error catalogue
│   ├── logger/logger.go
│   └── validator/validator.go
├── routes/routes.go                # Route registration & DI wiring
├── docs/                           # Swagger/OpenAPI generated files
├── Dockerfile                      # Multi-stage production build
├── docker-compose.yml
├── Makefile
└── .env.example
```

---

## Token Flow

```
Client                        Auth Service                   Redis
  │                                │                           │
  ├── POST /login ────────────────►│                           │
  │                                ├─ bcrypt.Compare           │
  │                                ├─ GenerateTokenPair        │
  │                                ├─ store refresh JTI ──────►│
  │◄── { access_token, refresh } ──┤                           │
  │                                │                           │
  ├── GET /profile (Bearer) ──────►│                           │
  │                                ├─ ValidateAccessToken      │
  │◄── user profile ───────────────┤                           │
  │                                │                           │
  ├── POST /refresh ──────────────►│                           │
  │                                ├─ ValidateRefreshToken     │
  │                                ├─ check JTI exists ───────►│
  │                                ├─ delete old JTI ─────────►│
  │                                ├─ GenerateTokenPair (new)  │
  │                                ├─ store new JTI ───────────►│
  │◄── { new_access, new_refresh } ┤                           │
```

Every `/refresh` call **invalidates** the old token. A stolen refresh token is single-use — reuse returns `401`.

---

## Security

| Feature | Implementation |
|---|---|
| Password hashing | bcrypt, 12 rounds |
| Access tokens | JWT HS256, 15-min expiry, stateless |
| Refresh tokens | JWT HS256, Redis JTI store, 7-day expiry |
| Token rotation | Old JTI deleted on every refresh |
| Account lockout | 5 failed attempts → 15-min lock |
| OAuth token encryption | AES-256-GCM at rest in Postgres |
| Rate limiting | Redis-backed per-IP, replica-safe |
| Email verification | 32-byte cryptographically random hex token |

---

## API

**Base URL:** `http://localhost:8080/api/v1`

| Method | Path | Auth | Rate Limit | Description |
|---|---|---|---|---|
| `GET` | `/health` | — | — | Health check |
| `POST` | `/signup` | — | 10/min | Register — email + password |
| `POST` | `/login` | — | 10/min | Login, receive token pair |
| `POST` | `/refresh` | — | 10/min | Rotate refresh token |
| `POST` | `/logout` | — | 10/min | Revoke refresh token |
| `GET` | `/verify-email?token=` | — | 5/min | Activate account |
| `GET` | `/oauth/google` | — | 10/min | Initiate Google OAuth |
| `GET` | `/oauth/google/callback` | — | 10/min | Google callback |
| `GET` | `/oauth/github` | — | 10/min | Initiate GitHub OAuth |
| `GET` | `/oauth/github/callback` | — | 10/min | GitHub callback |
| `GET` | `/profile` | JWT | 100/min | Current user profile |
| `GET` | `/admin` | JWT + admin | 100/min | Admin dashboard |

Full interactive docs: `http://localhost:8080/swagger/index.html`

### Examples

```bash
# Signup
curl -X POST http://localhost:8080/api/v1/signup \
  -H "Content-Type: application/json" \
  -d '{"name":"Alice","email":"alice@example.com","password":"Password1!"}'

# Login
curl -X POST http://localhost:8080/api/v1/login \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"Password1!"}'

# Authenticated request
curl http://localhost:8080/api/v1/profile \
  -H "Authorization: Bearer <access_token>"

# Rotate token
curl -X POST http://localhost:8080/api/v1/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"<refresh_token>"}'
```

> Account is **inactive** until email is verified. No tokens issued on signup.

---

## Database Schema

### `users`

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | Primary key |
| `email` | `VARCHAR(255)` | Unique |
| `password` | `VARCHAR(255)` | bcrypt hash — empty for OAuth users |
| `provider` | `VARCHAR(50)` | `local` · `google` · `github` |
| `role` | `VARCHAR(50)` | `user` · `admin` |
| `name` | `VARCHAR(255)` | |
| `avatar_url` | `VARCHAR(512)` | |
| `is_active` | `BOOLEAN` | False until email verified |
| `email_verified` | `BOOLEAN` | True for OAuth users |
| `failed_login_attempts` | `INT` | Resets on successful login |
| `locked_until` | `TIMESTAMPTZ` | Null if not locked |
| `created_at` / `updated_at` / `deleted_at` | `TIMESTAMPTZ` | GORM managed, soft delete |

### `oauth_accounts`

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | Primary key |
| `user_id` | `UUID` | FK → `users.id` |
| `provider` | `VARCHAR(50)` | `google` · `github` |
| `provider_user_id` | `VARCHAR(255)` | |
| `access_token` | `TEXT` | AES-256-GCM encrypted |
| `refresh_token` | `TEXT` | AES-256-GCM encrypted |
| `expires_at` | `TIMESTAMPTZ` | |

---

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `APP_PORT` | | `8080` | HTTP listen port |
| `APP_ENV` | | `development` | `development` or `production` |
| `APP_BASE_URL` | | `http://localhost:8080` | Public base URL |
| `CORS_ALLOWED_ORIGINS` | | `*` | Comma-separated origins |
| `DB_HOST` | | `localhost` | |
| `DB_PORT` | | `5432` | |
| `DB_USER` | | `postgres` | |
| `DB_PASSWORD` | ✅ | — | |
| `DB_NAME` | | `authdb` | |
| `DB_SSLMODE` | | `disable` | `verify-full` in production |
| `REDIS_HOST` | | `localhost` | |
| `REDIS_PORT` | | `6379` | |
| `REDIS_PASSWORD` | | — | |
| `JWT_ACCESS_SECRET` | ✅ | — | Min 32 chars |
| `JWT_REFRESH_SECRET` | ✅ | — | Different from access secret |
| `JWT_ACCESS_EXPIRY` | | `15m` | |
| `JWT_REFRESH_EXPIRY` | | `168h` | 7 days |
| `GOOGLE_CLIENT_ID` | OAuth | — | |
| `GOOGLE_CLIENT_SECRET` | OAuth | — | |
| `GITHUB_CLIENT_ID` | OAuth | — | |
| `GITHUB_CLIENT_SECRET` | OAuth | — | |
| `TOKEN_ENCRYPTION_KEY` | Prod | — | 32-byte AES key |

Generate secrets:

```bash
openssl rand -base64 64   # JWT_ACCESS_SECRET
openssl rand -base64 64   # JWT_REFRESH_SECRET
openssl rand -base64 32   # TOKEN_ENCRYPTION_KEY
```

---

## Quick Start

### Docker Compose *(recommended)*

```bash
git clone https://github.com/yourorg/auth-service.git
cd auth-service
cp .env.example .env
# fill in secrets in .env

docker compose up --build
```

API at `http://localhost:8080`.

### Local

```bash
# Start infra only
docker compose up -d postgres redis

go mod download
make run           # or: make dev  (Air live-reload)
```

### Verify

```bash
curl http://localhost:8080/health
# → {"status":"ok"}
```

---

## OAuth Setup

**Google** — [console.cloud.google.com/apis/credentials](https://console.cloud.google.com/apis/credentials)
Redirect URI: `http://localhost:8080/api/v1/oauth/google/callback`

**GitHub** — [github.com/settings/applications/new](https://github.com/settings/applications/new)
Callback URL: `http://localhost:8080/api/v1/oauth/github/callback`

---

## Makefile

```bash
make build           # Compile binary
make run             # Build and run
make dev             # Live-reload with Air
make test            # Run tests
make test-race       # With race detector
make test-coverage   # HTML coverage report
make lint            # golangci-lint
make fmt             # gofmt
make docker-up       # Start all Docker services
make docker-down     # Stop
make swagger         # Regenerate Swagger docs
make setup           # First-time setup
```

---


