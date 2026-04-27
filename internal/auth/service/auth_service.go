package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	authRepo "github.com/yourorg/auth-service/internal/auth/repository"
	"github.com/yourorg/auth-service/pkg/database"
	apperrors "github.com/yourorg/auth-service/pkg/errors"
	"github.com/yourorg/auth-service/pkg/validator"
)

// ---- Request / Response DTOs ----

type SignupRequest struct {
	Name     string `json:"name"     binding:"required,min=2,max=100"`
	Email    string `json:"email"    binding:"required,email"`
	Password string `json:"password" binding:"required,min=8"`
}

type LoginRequest struct {
	Email    string `json:"email"    binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type AuthResponse struct {
	User   UserResponse `json:"user"`
	Tokens *TokenPair   `json:"tokens"`
}

type UserResponse struct {
	ID        uuid.UUID `json:"id"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	Role      string    `json:"role"`
	Provider  string    `json:"provider"`
	AvatarURL string    `json:"avatar_url,omitempty"`
}

// OAuthUserInfo is extracted from OAuth provider callbacks.
// It carries both the user's profile and the provider's access tokens
// so they can be persisted for later API calls on behalf of the user.
type OAuthUserInfo struct {
	ProviderUserID       string
	Email                string
	Name                 string
	AvatarURL            string
	Provider             string
	ProviderToken        string     // provider access token
	ProviderRefreshToken string     // provider refresh token (if issued)
	ProviderTokenExpiry  *time.Time // when the provider token expires (nil = no expiry)
}

// ---- Service Interface ----

type AuthService interface {
	Signup(ctx context.Context, req *SignupRequest) (*AuthResponse, error)
	Login(ctx context.Context, req *LoginRequest) (*AuthResponse, error)
	RefreshTokens(ctx context.Context, refreshToken string) (*TokenPair, error)
	Logout(ctx context.Context, refreshToken string) error
	GetUserByID(ctx context.Context, id uuid.UUID) (*UserResponse, error)

	// OAuth
	HandleOAuthLogin(ctx context.Context, info *OAuthUserInfo) (*AuthResponse, error)
}

type authService struct {
	repo         authRepo.AuthRepository
	tokenService TokenService
}

func NewAuthService(repo authRepo.AuthRepository, tokenSvc TokenService) AuthService {
	return &authService{
		repo:         repo,
		tokenService: tokenSvc,
	}
}

func (s *authService) Signup(ctx context.Context, req *SignupRequest) (*AuthResponse, error) {
	// Sanitize + validate email
	email := validator.SanitizeEmail(req.Email)
	if !validator.ValidateEmail(email) {
		return nil, apperrors.WithDetail(apperrors.ErrBadRequest, "invalid email format")
	}

	// Validate password complexity
	if ok, msg := validator.ValidatePassword(req.Password); !ok {
		return nil, apperrors.WithDetail(apperrors.ErrBadRequest, msg)
	}

	// Check for existing user
	existing, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil && err != apperrors.ErrUserNotFound {
		return nil, err
	}
	if existing != nil {
		return nil, apperrors.ErrUserAlreadyExists
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	user := &database.User{
		Email:    email,
		Password: string(hashedPassword),
		Name:     req.Name,
		Provider: database.ProviderLocal,
		Role:     database.RoleUser,
	}

	if err := s.repo.CreateUser(ctx, user); err != nil {
		return nil, err
	}

	tokens, err := s.tokenService.GenerateTokenPair(ctx, user.ID, user.Email, user.Role)
	if err != nil {
		return nil, err
	}

	return &AuthResponse{
		User:   mapUserToResponse(user),
		Tokens: tokens,
	}, nil
}

func (s *authService) Login(ctx context.Context, req *LoginRequest) (*AuthResponse, error) {
	email := validator.SanitizeEmail(req.Email)

	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		if err == apperrors.ErrUserNotFound {
			return nil, apperrors.ErrInvalidCredentials
		}
		return nil, err
	}

	if !user.IsActive {
		return nil, apperrors.ErrAccountInactive
	}

	// Only local accounts have passwords
	if user.Provider != database.ProviderLocal {
		return nil, apperrors.WithDetail(apperrors.ErrBadRequest,
			fmt.Sprintf("this account uses %s login", user.Provider))
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		return nil, apperrors.ErrInvalidCredentials
	}

	tokens, err := s.tokenService.GenerateTokenPair(ctx, user.ID, user.Email, user.Role)
	if err != nil {
		return nil, err
	}

	return &AuthResponse{
		User:   mapUserToResponse(user),
		Tokens: tokens,
	}, nil
}

func (s *authService) RefreshTokens(ctx context.Context, refreshToken string) (*TokenPair, error) {
	return s.tokenService.RotateRefreshToken(ctx, refreshToken)
}

func (s *authService) Logout(ctx context.Context, refreshToken string) error {
	return s.tokenService.RevokeRefreshToken(ctx, refreshToken)
}

func (s *authService) GetUserByID(ctx context.Context, id uuid.UUID) (*UserResponse, error) {
	user, err := s.repo.GetUserByID(ctx, id)
	if err != nil {
		return nil, err
	}
	resp := mapUserToResponse(user)
	return &resp, nil
}

func (s *authService) HandleOAuthLogin(ctx context.Context, info *OAuthUserInfo) (*AuthResponse, error) {
	email := validator.SanitizeEmail(info.Email)

	// 1. Check if OAuth account already linked
	oauthAccount, err := s.repo.GetOAuthAccount(ctx, info.Provider, info.ProviderUserID)
	if err != nil {
		return nil, err
	}

	var user *database.User

	if oauthAccount != nil {
		// Existing OAuth user — load their full record
		user, err = s.repo.GetUserByID(ctx, oauthAccount.UserID)
		if err != nil {
			return nil, err
		}
	} else {
		// Try to find user by email (link accounts if email matches)
		user, err = s.repo.GetUserByEmail(ctx, email)
		if err != nil && err != apperrors.ErrUserNotFound {
			return nil, err
		}

		if user == nil {
			// Auto-create new user
			user = &database.User{
				Email:     email,
				Name:      info.Name,
				AvatarURL: info.AvatarURL,
				Provider:  info.Provider,
				Role:      database.RoleUser,
			}
			if err := s.repo.CreateUser(ctx, user); err != nil {
				return nil, err
			}
		}
	}

	// Guard: reject inactive accounts BEFORE creating the OAuth link or issuing tokens.
	// This check covers ALL paths — returning OAuth user, email-matched user, and new user.
	if !user.IsActive {
		return nil, apperrors.ErrAccountInactive
	}

	// Upsert the OAuth account link and persist the latest provider tokens.
	// Using Upsert ensures provider access/refresh tokens stay up-to-date on every login.
	oauthLink := &database.OAuthAccount{
		UserID:         user.ID,
		Provider:       info.Provider,
		ProviderUserID: info.ProviderUserID,
		AccessToken:    info.ProviderToken,
		RefreshToken:   info.ProviderRefreshToken,
		ExpiresAt:      info.ProviderTokenExpiry,
	}
	if err := s.repo.UpsertOAuthAccount(ctx, oauthLink); err != nil {
		return nil, err
	}

	tokens, err := s.tokenService.GenerateTokenPair(ctx, user.ID, user.Email, user.Role)
	if err != nil {
		return nil, err
	}

	return &AuthResponse{
		User:   mapUserToResponse(user),
		Tokens: tokens,
	}, nil
}

func mapUserToResponse(u *database.User) UserResponse {
	return UserResponse{
		ID:        u.ID,
		Email:     u.Email,
		Name:      u.Name,
		Role:      u.Role,
		Provider:  u.Provider,
		AvatarURL: u.AvatarURL,
	}
}
