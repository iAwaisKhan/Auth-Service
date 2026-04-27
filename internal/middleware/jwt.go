package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/yourorg/auth-service/internal/auth/service"
	apperrors "github.com/yourorg/auth-service/pkg/errors"
)

const (
	AuthorizationHeader = "Authorization"
	BearerPrefix        = "Bearer "
	ContextUserID       = "userID"
	ContextEmail        = "email"
	ContextRole         = "role"
)

// JWTAuth extracts and validates the Bearer token from the Authorization header
func JWTAuth(tokenSvc service.TokenService) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader(AuthorizationHeader)
		if authHeader == "" || !strings.HasPrefix(authHeader, BearerPrefix) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, apperrors.ErrInvalidToken)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, BearerPrefix)
		claims, err := tokenSvc.ValidateAccessToken(tokenString)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, apperrors.ErrInvalidToken)
			return
		}

		// Inject claims into context
		c.Set(ContextUserID, claims.UserID)
		c.Set(ContextEmail, claims.Email)
		c.Set(ContextRole, claims.Role)

		c.Next()
	}
}

// RequireRole enforces role-based access control.
// Pass one or more allowed roles; the user must have at least one.
func RequireRole(roles ...string) gin.HandlerFunc {
	roleSet := make(map[string]struct{}, len(roles))
	for _, r := range roles {
		roleSet[r] = struct{}{}
	}

	return func(c *gin.Context) {
		userRole, exists := c.Get(ContextRole)
		if !exists {
			c.AbortWithStatusJSON(http.StatusUnauthorized, apperrors.ErrInvalidToken)
			return
		}

		if _, ok := roleSet[userRole.(string)]; !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, apperrors.ErrForbidden)
			return
		}

		c.Next()
	}
}
