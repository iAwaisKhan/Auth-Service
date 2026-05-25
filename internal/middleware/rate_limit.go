package middleware

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/ulule/limiter/v3"
	ginLimiter "github.com/ulule/limiter/v3/drivers/middleware/gin"
)

// RateLimit returns a Gin middleware for the given rate format string.
//
// --- 2.2 fix: fail-closed, not fail-open ---
// Invalid rate format strings now panic at startup rather than silently
// passing all traffic. This ensures misconfiguration is caught immediately
// rather than discovered during a load test or security incident.
//
// Valid format examples: "10-M" (10/min), "100-S" (100/sec), "1000-H" (1000/hr)
func RateLimit(store limiter.Store, rateFormat string) gin.HandlerFunc {
	rate, err := limiter.NewRateFromFormatted(rateFormat)
	if err != nil {
		// Panic at startup — do NOT fail open. A bad rate format means
		// the rate limiter is not running, which is a security defect.
		panic(fmt.Sprintf("invalid rate limit format %q: %v — fix the rate string and restart", rateFormat, err))
	}

	instance := limiter.New(store, rate)
	return ginLimiter.NewMiddleware(instance, ginLimiter.WithLimitReachedHandler(func(c *gin.Context) {
		c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
			"message": "too many requests — please slow down",
		})
	}))
}
