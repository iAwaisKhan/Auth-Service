package middleware

import (
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	"github.com/yourorg/auth-service/pkg/config"
)

// CORS returns a CORS handler configured from AppConfig.
// In development (AllowedOrigins == ["*"]) credentials are not allowed
// because browsers reject wildcard+credentials.
// In production, set CORS_ALLOWED_ORIGINS to your frontend domain(s)
// so that the oauth_state cookie can be sent on cross-origin requests.
func CORS(cfg config.AppConfig) gin.HandlerFunc {
	origins := cfg.AllowedOrigins
	if len(origins) == 0 {
		origins = []string{"*"}
	}

	// AllowCredentials=true requires explicit origins (not "*").
	allowCredentials := !(len(origins) == 1 && origins[0] == "*")

	return cors.New(cors.Config{
		AllowOrigins:     origins,
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization", "X-Request-ID"},
		ExposeHeaders:    []string{"Content-Length", "X-Request-ID"},
		AllowCredentials: allowCredentials,
		MaxAge:           12 * time.Hour,
	})
}
