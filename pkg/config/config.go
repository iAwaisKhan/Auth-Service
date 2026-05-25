package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

// weakSecrets is a blocklist of obviously-weak JWT secret values.
var weakSecrets = []string{
	"secret", "changeme", "password", "letmein", "test", "dev",
	"development", "production", "jwt", "auth", "token", "key",
	"supersecret", "mysecret", "yoursecret", "topsecret",
}

type Config struct {
	App      AppConfig
	Database DatabaseConfig
	Redis    RedisConfig
	JWT      JWTConfig
	OAuth    OAuthConfig
}

type AppConfig struct {
	Port           string
	Env            string
	BaseURL        string
	AllowedOrigins []string // CORS: comma-separated via CORS_ALLOWED_ORIGINS env var
}

type DatabaseConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	Name     string
	SSLMode  string
	TimeZone string
}

type RedisConfig struct {
	Host     string
	Port     string
	Password string
	DB       int
}

type JWTConfig struct {
	AccessSecret       string
	RefreshSecret      string
	AccessTokenExpiry  time.Duration
	RefreshTokenExpiry time.Duration
}

type OAuthConfig struct {
	GoogleClientID     string
	GoogleClientSecret string
	GoogleRedirectURL  string
	GithubClientID     string
	GithubClientSecret string
	GithubRedirectURL  string
	// TokenEncryptionKey is a 32-byte AES-256 key (base64-encoded) used to
	// encrypt OAuth provider tokens at rest. Required in production.
	TokenEncryptionKey []byte
}

func Load() (*Config, error) {
	// Load .env file (ignore error in production where env vars are set directly)
	_ = godotenv.Load()

	cfg := &Config{}

	// App
	cfg.App.Port = getEnv("APP_PORT", "8080")
	cfg.App.Env = getEnv("APP_ENV", "development")
	cfg.App.BaseURL = getEnv("APP_BASE_URL", "http://localhost:8080")

	// CORS allowed origins — comma-separated, defaults to wildcard (dev only)
	originsRaw := getEnv("CORS_ALLOWED_ORIGINS", "*")
	for _, o := range strings.Split(originsRaw, ",") {
		if trimmed := strings.TrimSpace(o); trimmed != "" {
			cfg.App.AllowedOrigins = append(cfg.App.AllowedOrigins, trimmed)
		}
	}

	// Database
	cfg.Database.Host = getEnv("DB_HOST", "localhost")
	cfg.Database.Port = getEnv("DB_PORT", "5432")
	cfg.Database.User = getEnv("DB_USER", "postgres")
	cfg.Database.Password = getEnv("DB_PASSWORD", "")
	cfg.Database.Name = getEnv("DB_NAME", "authdb")
	cfg.Database.SSLMode = getEnv("DB_SSLMODE", "disable")
	cfg.Database.TimeZone = getEnv("DB_TIMEZONE", "UTC")

	// --- 2.2 fix / hardened: fail hard on DB_SSLMODE=disable in production ---
	if cfg.App.Env == "production" && strings.ToLower(cfg.Database.SSLMode) == "disable" {
		return nil, fmt.Errorf("DB_SSLMODE=disable is not allowed in production — set DB_SSLMODE=require or verify-full")
	}

	// Redis
	cfg.Redis.Host = getEnv("REDIS_HOST", "localhost")
	cfg.Redis.Port = getEnv("REDIS_PORT", "6379")
	cfg.Redis.Password = getEnv("REDIS_PASSWORD", "")
	redisDB, _ := strconv.Atoi(getEnv("REDIS_DB", "0"))
	cfg.Redis.DB = redisDB

	// JWT
	accessSecret := getEnv("JWT_ACCESS_SECRET", "")
	if accessSecret == "" {
		return nil, fmt.Errorf("JWT_ACCESS_SECRET is required")
	}
	// --- 2.2 fix: enforce minimum 32-char JWT secrets ---
	if err := validateSecret("JWT_ACCESS_SECRET", accessSecret); err != nil {
		return nil, err
	}
	cfg.JWT.AccessSecret = accessSecret

	refreshSecret := getEnv("JWT_REFRESH_SECRET", "")
	if refreshSecret == "" {
		return nil, fmt.Errorf("JWT_REFRESH_SECRET is required")
	}
	if err := validateSecret("JWT_REFRESH_SECRET", refreshSecret); err != nil {
		return nil, err
	}
	cfg.JWT.RefreshSecret = refreshSecret

	accessExpiry, err := time.ParseDuration(getEnv("JWT_ACCESS_EXPIRY", "15m"))
	if err != nil {
		return nil, fmt.Errorf("invalid JWT_ACCESS_EXPIRY: %w", err)
	}
	cfg.JWT.AccessTokenExpiry = accessExpiry

	refreshExpiry, err := time.ParseDuration(getEnv("JWT_REFRESH_EXPIRY", "168h"))
	if err != nil {
		return nil, fmt.Errorf("invalid JWT_REFRESH_EXPIRY: %w", err)
	}
	cfg.JWT.RefreshTokenExpiry = refreshExpiry

	// OAuth
	cfg.OAuth.GoogleClientID = getEnv("GOOGLE_CLIENT_ID", "")
	cfg.OAuth.GoogleClientSecret = getEnv("GOOGLE_CLIENT_SECRET", "")
	cfg.OAuth.GoogleRedirectURL = getEnv("GOOGLE_REDIRECT_URL", cfg.App.BaseURL+"/api/v1/oauth/google/callback")
	cfg.OAuth.GithubClientID = getEnv("GITHUB_CLIENT_ID", "")
	cfg.OAuth.GithubClientSecret = getEnv("GITHUB_CLIENT_SECRET", "")
	cfg.OAuth.GithubRedirectURL = getEnv("GITHUB_REDIRECT_URL", cfg.App.BaseURL+"/api/v1/oauth/github/callback")

	// TOKEN_ENCRYPTION_KEY: base64-encoded 32-byte AES-256 key for OAuth token encryption.
	// Required in production; optional in development (tokens stored plaintext with a warning).
	tokenKeyB64 := getEnv("TOKEN_ENCRYPTION_KEY", "")
	if tokenKeyB64 == "" {
		if cfg.App.Env == "production" {
			return nil, fmt.Errorf("TOKEN_ENCRYPTION_KEY is required in production — generate with: openssl rand -base64 32")
		}
		fmt.Println("WARNING: TOKEN_ENCRYPTION_KEY not set — OAuth tokens stored unencrypted (development only)")
	} else {
		key, err := base64.StdEncoding.DecodeString(tokenKeyB64)
		if err != nil {
			return nil, fmt.Errorf("TOKEN_ENCRYPTION_KEY: invalid base64: %w", err)
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("TOKEN_ENCRYPTION_KEY must decode to exactly 32 bytes (got %d) — generate with: openssl rand -base64 32", len(key))
		}
		cfg.OAuth.TokenEncryptionKey = key
	}

	return cfg, nil
}

// validateSecret enforces minimum length and blocklist for JWT secrets.
// --- 2.2 fix: secret strength validation ---
func validateSecret(name, secret string) error {
	const minLen = 32
	if len(secret) < minLen {
		return fmt.Errorf("%s must be at least %d characters (got %d) — use a strong random value", name, minLen, len(secret))
	}
	lower := strings.ToLower(secret)
	for _, weak := range weakSecrets {
		if lower == weak || strings.Contains(lower, weak) && len(secret) < 40 {
			return fmt.Errorf("%s appears to be a weak/default value — use a cryptographically random secret", name)
		}
	}
	return nil
}

func (d DatabaseConfig) DSN() string {
	return fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%s sslmode=%s TimeZone=%s",
		d.Host, d.User, d.Password, d.Name, d.Port, d.SSLMode, d.TimeZone,
	)
}

func (r RedisConfig) Addr() string {
	return fmt.Sprintf("%s:%s", r.Host, r.Port)
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}
