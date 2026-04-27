package middleware

import (
	"github.com/redis/go-redis/v9"
	"github.com/yourorg/auth-service/pkg/config"
)

// newRedisClientForLimiter creates a go-redis client compatible with ulule/limiter
func newRedisClientForLimiter(cfg config.RedisConfig) redis.UniversalClient {
	return redis.NewClient(&redis.Options{
		Addr:     cfg.Addr(),
		Password: cfg.Password,
		DB:       cfg.DB,
	})
}
