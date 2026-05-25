package routes

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/ulule/limiter/v3"
	"gorm.io/gorm"

	authHandler "github.com/yourorg/auth-service/internal/auth/handler"
	authRepo "github.com/yourorg/auth-service/internal/auth/repository"
	authService "github.com/yourorg/auth-service/internal/auth/service"
	"github.com/yourorg/auth-service/internal/middleware"
	"github.com/yourorg/auth-service/pkg/cache"
	"github.com/yourorg/auth-service/pkg/config"
	"github.com/yourorg/auth-service/pkg/crypto"
	"github.com/yourorg/auth-service/pkg/logger"
)

func Setup(
	cfg *config.Config,
	db *gorm.DB,
	redisClient *cache.RedisClient,
	log *logger.Logger,
	rateLimitStore limiter.Store,
) *gin.Engine {
	if cfg.App.Env == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()

	// ── Global middleware ──────────────────────────────────────────────────────
	router.Use(middleware.Recovery(log))
	router.Use(middleware.RequestLogger(log))
	router.Use(middleware.CORS(cfg.App))

	// ── Build optional token cipher (nil = dev mode, no encryption) ───────────
	var tokenCipher *crypto.TokenCipher
	if len(cfg.OAuth.TokenEncryptionKey) == 32 {
		var err error
		tokenCipher, err = crypto.NewTokenCipher(cfg.OAuth.TokenEncryptionKey)
		if err != nil {
			// Config validation already ensures the key is valid; this is a safeguard.
			panic("failed to init token cipher: " + err.Error())
		}
	}

	// ── Dependency wiring ──────────────────────────────────────────────────────
	repo := authRepo.NewAuthRepository(db, tokenCipher)
	tokenSvc := authService.NewTokenService(cfg.JWT, redisClient)
	oauthSvc := authService.NewOAuthService(cfg.OAuth)
	authSvc := authService.NewAuthService(repo, tokenSvc)
	handler := authHandler.NewAuthHandler(authSvc, oauthSvc, log, cfg.App.Env == "production")

	// ── Rate limiters ──────────────────────────────────────────────────────────
	// NOTE: invalid format strings now panic at startup (fail-closed, 2.2 fix)
	authLimiter := middleware.RateLimit(rateLimitStore, "10-M")
	apiLimiter := middleware.RateLimit(rateLimitStore, "100-M")
	// --- 2.2 fix: stricter limiter for verification endpoints ---
	verifyLimiter := middleware.RateLimit(rateLimitStore, "5-M")

	// ── Health check ──────────────────────────────────────────────────────────
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// ── API v1 ────────────────────────────────────────────────────────────────
	v1 := router.Group("/api/v1")
	{
		// Public auth routes (rate-limited strictly)
		auth := v1.Group("")
		auth.Use(authLimiter)
		{
			auth.POST("/signup", handler.Signup)
			auth.POST("/login", handler.Login)
			auth.POST("/refresh", handler.Refresh)
			auth.POST("/logout", handler.Logout)
		}

		// --- 2.2 fix: email verification route (stricter limiter) ---
		v1.GET("/verify-email", verifyLimiter, handler.VerifyEmail)

		// OAuth routes
		oauth := v1.Group("/oauth")
		oauth.Use(authLimiter)
		{
			oauth.GET("/google", handler.GoogleOAuth)
			oauth.GET("/google/callback", handler.GoogleCallback)
			oauth.GET("/github", handler.GithubOAuth)
			oauth.GET("/github/callback", handler.GithubCallback)
		}

		// Protected routes — requires valid JWT
		protected := v1.Group("")
		protected.Use(apiLimiter)
		protected.Use(middleware.JWTAuth(tokenSvc))
		{
			protected.GET("/profile", handler.GetProfile)
		}

		// Admin-only routes
		admin := v1.Group("/admin")
		admin.Use(apiLimiter)
		admin.Use(middleware.JWTAuth(tokenSvc))
		admin.Use(middleware.RequireRole("admin"))
		{
			admin.GET("", handler.AdminDashboard)
		}
	}

	router.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{"message": "route not found"})
	})

	return router
}
