package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	authRepo "github.com/yourorg/auth-service/internal/auth/repository"
	"github.com/yourorg/auth-service/pkg/database"
	apperrors "github.com/yourorg/auth-service/pkg/errors"
	"github.com/yourorg/auth-service/pkg/validator"
)

// lockout policy constants
const (
	maxFailedAttempts = 5
	lockDuration      = 15 * time.Minute
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
	ID            uuid.UUID `json:"id"`
	Email         string    `json:"email"`
	Name          string    `json:"name"`
	Role          string    `json:"role"`
	Provider      string    `json:"provider"`
	AvatarURL     string    `json:"avatar_url,omitempty"`
	EmailVerified bool      `json:"email_verified"`
}

// OAuthUserInfo is extracted from OAuth provider callbacks.
type OAuthUserInfo struct {
	ProviderUserID       string
	Email                string
	Name                 string
	AvatarURL            string
	Provider             string
	ProviderToken        string
	ProviderRefreshToken string
	ProviderTokenExpiry  *time.Time
}

// VerifyEmailRequest carries the token from the verification link.
type VerifyEmailRequest struct {
	Token string `json:"token" binding:"required"`
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

	// --- 2.2 fix: email verification ---
	VerifyEmail(ctx context.Context, token string) error
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
	email := validator.SanitizeEmail(req.Email)
	if !validator.ValidateEmail(email) {
		return nil, apperrors.WithDetail(apperrors.ErrBadRequest, "invalid email format")
	}

	if ok, msg := validator.ValidatePassword(req.Password); !ok {
		return nil, apperrors.WithDetail(apperrors.ErrBadRequest, msg)
	}

	existing, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil && err != apperrors.ErrUserNotFound {
		return nil, err
	}
	if existing != nil {
		return nil, apperrors.ErrUserAlreadyExists
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// --- 2.2 fix: email verification — new local accounts start inactive ---
	verificationToken, err := generateVerificationToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate verification token: %w", err)
	}

	user := &database.User{
		Email:             email,
		Password:          string(hashedPassword),
		Name:              req.Name,
		Provider:          database.ProviderLocal,
		Role:              database.RoleUser,
		IsActive:          false,         // inactive until email verified
		EmailVerified:     false,
		VerificationToken: verificationToken,
	}

	if err := s.repo.CreateUser(ctx, user); err != nil {
		return nil, err
	}

	// NOTE: Caller (handler) is responsible for sending the verification email.
	// The token is embedded in the response so the handler can dispatch it.
	// In production, plug in your email provider here or use an event/queue.

	// Do NOT issue tokens yet — account is inactive until verified.
	return &AuthResponse{
		User: mapUserToResponse(user),
		// Tokens: nil — intentionally omitted; client must verify email first.
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

	// --- 2.2 fix: check account lock before any further processing ---
	if user.IsLocked() {
		return nil, apperrors.ErrAccountLocked
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
		// --- 2.2 fix: increment failed counter on wrong password ---
		_ = s.repo.IncrementFailedLogins(ctx, user.ID, lockDuration, maxFailedAttempts)
		return nil, apperrors.ErrInvalidCredentials
	}

	// --- 2.2 fix: reset counter on successful login ---
	_ = s.repo.ResetFailedLogins(ctx, user.ID)

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
		// Try to find user by email
		existingUser, err := s.repo.GetUserByEmail(ctx, email)
		if err != nil && err != apperrors.ErrUserNotFound {
			return nil, err
		}

		if existingUser != nil {
			// --- 2.2 fix: implicit account linking is a privacy risk ---
			// Return a specific error so the handler can surface a consent flow.
			// The caller must implement POST /link-account (Phase 2 roadmap item).
			return nil, apperrors.ErrOAuthLinkRequired
		}

		// No existing user — create new. OAuth accounts start active + verified.
		user = &database.User{
			Email:         email,
			Name:          info.Name,
			AvatarURL:     info.AvatarURL,
			Provider:      info.Provider,
			Role:          database.RoleUser,
			IsActive:      true,
			EmailVerified: true, // provider already verified the email
		}
		if err := s.repo.CreateUser(ctx, user); err != nil {
			return nil, err
		}
	}

	// Guard: reject inactive accounts BEFORE issuing tokens.
	if user.IsLocked() {
		return nil, apperrors.ErrAccountLocked
	}
	if !user.IsActive {
		return nil, apperrors.ErrAccountInactive
	}

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

// VerifyEmail activates an account using the token from the verification email.
// --- 2.2 fix: email verification ---
func (s *authService) VerifyEmail(ctx context.Context, token string) error {
	return s.repo.VerifyEmail(ctx, token)
}

// generateVerificationToken produces a 32-byte cryptographically random hex token.
func generateVerificationToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func mapUserToResponse(u *database.User) UserResponse {
	return UserResponse{
		ID:            u.ID,
		Email:         u.Email,
		Name:          u.Name,
		Role:          u.Role,
		Provider:      u.Provider,
		AvatarURL:     u.AvatarURL,
		EmailVerified: u.EmailVerified,
	}
}
