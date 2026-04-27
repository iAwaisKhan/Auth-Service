package service

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/yourorg/auth-service/pkg/cache"
	"github.com/yourorg/auth-service/pkg/config"
	apperrors "github.com/yourorg/auth-service/pkg/errors"
)

const (
	refreshTokenKeyPrefix = "refresh_token:"
	blacklistKeyPrefix    = "blacklist:"
)

// Claims represents JWT claims
type Claims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

// TokenPair holds access and refresh tokens
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"` // seconds
}

type TokenService interface {
	GenerateTokenPair(ctx context.Context, userID uuid.UUID, email, role string) (*TokenPair, error)
	ValidateAccessToken(tokenString string) (*Claims, error)
	ValidateRefreshToken(ctx context.Context, tokenString string) (*Claims, error)
	RevokeRefreshToken(ctx context.Context, tokenString string) error
	RotateRefreshToken(ctx context.Context, oldRefreshToken string) (*TokenPair, error)
}

type tokenService struct {
	cfg   config.JWTConfig
	redis *cache.RedisClient
}

func NewTokenService(cfg config.JWTConfig, redis *cache.RedisClient) TokenService {
	return &tokenService{cfg: cfg, redis: redis}
}

func (s *tokenService) GenerateTokenPair(ctx context.Context, userID uuid.UUID, email, role string) (*TokenPair, error) {
	now := time.Now()

	// Access token
	accessClaims := &Claims{
		UserID: userID.String(),
		Email:  email,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(s.cfg.AccessTokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "auth-service",
			Subject:   userID.String(),
		},
	}

	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims).
		SignedString([]byte(s.cfg.AccessSecret))
	if err != nil {
		return nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	// Refresh token — embed a jti (JWT ID) so we can track it in Redis
	jti := uuid.New().String()
	refreshClaims := &Claims{
		UserID: userID.String(),
		Email:  email,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(s.cfg.RefreshTokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "auth-service",
			Subject:   userID.String(),
			ID:        jti,
		},
	}

	refreshToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims).
		SignedString([]byte(s.cfg.RefreshSecret))
	if err != nil {
		return nil, fmt.Errorf("failed to sign refresh token: %w", err)
	}

	// Store refresh token JTI in Redis
	key := refreshTokenKeyPrefix + jti
	if err := s.redis.Set(ctx, key, userID.String(), s.cfg.RefreshTokenExpiry); err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(s.cfg.AccessTokenExpiry.Seconds()),
	}, nil
}

func (s *tokenService) ValidateAccessToken(tokenString string) (*Claims, error) {
	return s.parseToken(tokenString, s.cfg.AccessSecret)
}

func (s *tokenService) ValidateRefreshToken(ctx context.Context, tokenString string) (*Claims, error) {
	claims, err := s.parseToken(tokenString, s.cfg.RefreshSecret)
	if err != nil {
		return nil, err
	}

	// Check if token JTI still exists in Redis (not revoked)
	key := refreshTokenKeyPrefix + claims.ID
	exists, err := s.redis.Exists(ctx, key)
	if err != nil {
		return nil, apperrors.ErrInternalServer
	}
	if !exists {
		return nil, apperrors.ErrInvalidToken
	}

	return claims, nil
}

func (s *tokenService) RevokeRefreshToken(ctx context.Context, tokenString string) error {
	claims, err := s.parseToken(tokenString, s.cfg.RefreshSecret)
	if err != nil {
		return err
	}

	key := refreshTokenKeyPrefix + claims.ID
	return s.redis.Delete(ctx, key)
}

// RotateRefreshToken implements token rotation — old token is revoked and a new pair is issued
func (s *tokenService) RotateRefreshToken(ctx context.Context, oldRefreshToken string) (*TokenPair, error) {
	claims, err := s.ValidateRefreshToken(ctx, oldRefreshToken)
	if err != nil {
		return nil, err
	}

	// Revoke old token first
	if err := s.RevokeRefreshToken(ctx, oldRefreshToken); err != nil {
		return nil, err
	}

	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		return nil, apperrors.ErrInvalidToken
	}

	// Issue new pair
	return s.GenerateTokenPair(ctx, userID, claims.Email, claims.Role)
}

func (s *tokenService) parseToken(tokenString, secret string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(secret), nil
	})

	if err != nil {
		return nil, apperrors.ErrInvalidToken
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, apperrors.ErrInvalidToken
	}

	return claims, nil
}
