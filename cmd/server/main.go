package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/yourorg/auth-service/internal/middleware"
	"github.com/yourorg/auth-service/pkg/cache"
	"github.com/yourorg/auth-service/pkg/config"
	"github.com/yourorg/auth-service/pkg/database"
	"github.com/yourorg/auth-service/pkg/logger"
	"github.com/yourorg/auth-service/routes"
)

// @title           Auth Microservice API
// @version         1.0
// @description     Production-ready Authentication Microservice with JWT, OAuth, and RBAC
// @termsOfService  http://swagger.io/terms/

// @contact.name   API Support
// @contact.email  support@yourorg.com

// @license.name  Apache 2.0
// @license.url   http://www.apache.org/licenses/LICENSE-2.0.html

// @host      localhost:8080
// @BasePath  /api/v1

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token.
func main() {
	// Load config
	cfg, err := config.Load()
	if err != nil {
		panic("failed to load config: " + err.Error())
	}

	// Init logger
	log := logger.New(cfg.App.Env)
	defer log.Sync()

	// Init database
	db, err := database.NewPostgres(cfg.Database)
	if err != nil {
		log.Fatal("failed to connect to database", logger.Error(err))
	}

	// Run migrations
	if err := database.AutoMigrate(db); err != nil {
		log.Fatal("failed to run migrations", logger.Error(err))
	}

	// Init Redis
	redisClient, err := cache.NewRedis(cfg.Redis)
	if err != nil {
		log.Fatal("failed to connect to redis", logger.Error(err))
	}
	defer redisClient.Close()

	// Init rate limiter store
	rateLimitStore, err := middleware.NewRateLimitStore(cfg.Redis)
	if err != nil {
		log.Fatal("failed to init rate limiter", logger.Error(err))
	}

	// Setup router
	router := routes.Setup(cfg, db, redisClient, log, rateLimitStore)

	// Create HTTP server
	srv := &http.Server{
		Addr:         ":" + cfg.App.Port,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		log.Info("server starting", logger.String("port", cfg.App.Port), logger.String("env", cfg.App.Env))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("failed to start server", logger.Error(err))
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("server forced to shutdown", logger.Error(err))
	}

	log.Info("server exited cleanly")
}
