package middleware

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/ulule/limiter/v3"
	ginlimiter "github.com/ulule/limiter/v3/drivers/middleware/gin"
	redisstore "github.com/ulule/limiter/v3/drivers/store/redis"

	"github.com/yourorg/auth-service/pkg/config"
)

// NewRateLimitStore creates a Redis-backed limiter store
func NewRateLimitStore(cfg config.RedisConfig) (limiter.Store, error) {
	// Import redis client compatible with ulule/limiter
	// We create a separate client here for the limiter
	client := newRedisClientForLimiter(cfg)
	store, err := redisstore.NewStoreWithOptions(client, limiter.StoreOptions{
		Prefix:          "rate_limit",
		MaxRetry:        3,
		CleanUpInterval: 0,
	})
	return store, err
}

// RateLimit returns a Gin middleware for rate limiting.
// rate format: "5-S" (5 per second), "100-M" (100 per minute), "1000-H" (1000 per hour)
func RateLimit(store limiter.Store, rateStr string) gin.HandlerFunc {
	rate, err := limiter.NewRateFromFormatted(rateStr)
	if err != nil {
		// Fail open — but log a prominent warning so it doesn't go unnoticed.
		log.Printf("[WARN] rate_limit: invalid rate format %q: %v — rate limiting is DISABLED for this route", rateStr, err)
		return func(c *gin.Context) { c.Next() }
	}

	instance := limiter.New(store, rate)
	middleware := ginlimiter.NewMiddleware(instance, ginlimiter.WithLimitReachedHandler(func(c *gin.Context) {
		c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
			"message": "rate limit exceeded, please slow down",
		})
	}))

	return middleware
}
