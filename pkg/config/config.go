package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

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
	GoogleClientID      string
	GoogleClientSecret  string
	GoogleRedirectURL   string
	GithubClientID      string
	GithubClientSecret  string
	GithubRedirectURL   string
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
	cfg.JWT.AccessSecret = accessSecret

	refreshSecret := getEnv("JWT_REFRESH_SECRET", "")
	if refreshSecret == "" {
		return nil, fmt.Errorf("JWT_REFRESH_SECRET is required")
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

	return cfg, nil
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
