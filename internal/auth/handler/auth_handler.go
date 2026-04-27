package handler

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/yourorg/auth-service/internal/auth/service"
	apperrors "github.com/yourorg/auth-service/pkg/errors"
	"github.com/yourorg/auth-service/pkg/logger"
)

type AuthHandler struct {
	authSvc      service.AuthService
	oauthSvc     service.OAuthService
	log          *logger.Logger
	secureCookie bool // true in production: sets Secure flag on OAuth state cookie
}

func NewAuthHandler(
	authSvc service.AuthService,
	oauthSvc service.OAuthService,
	log *logger.Logger,
	secureCookie bool,
) *AuthHandler {
	return &AuthHandler{
		authSvc:      authSvc,
		oauthSvc:     oauthSvc,
		log:          log,
		secureCookie: secureCookie,
	}
}

func (h *AuthHandler) Signup(c *gin.Context) {
	var req service.SignupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, apperrors.WithDetail(apperrors.ErrBadRequest, err.Error()))
		return
	}
	resp, err := h.authSvc.Signup(c.Request.Context(), &req)
	if err != nil {
		h.log.Error("signup failed", logger.Error(err))
		respondError(c, err)
		return
	}
	c.JSON(http.StatusCreated, resp)
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req service.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, apperrors.WithDetail(apperrors.ErrBadRequest, err.Error()))
		return
	}
	resp, err := h.authSvc.Login(c.Request.Context(), &req)
	if err != nil {
		h.log.Warn("login failed", logger.Error(err))
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, resp)
}

func (h *AuthHandler) Refresh(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, apperrors.WithDetail(apperrors.ErrBadRequest, err.Error()))
		return
	}
	tokens, err := h.authSvc.RefreshTokens(c.Request.Context(), req.RefreshToken)
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, tokens)
}

func (h *AuthHandler) Logout(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		respondError(c, apperrors.WithDetail(apperrors.ErrBadRequest, err.Error()))
		return
	}
	if err := h.authSvc.Logout(c.Request.Context(), req.RefreshToken); err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "logged out successfully"})
}

func (h *AuthHandler) GoogleOAuth(c *gin.Context) {
	state, err := generateState()
	if err != nil {
		h.log.Error("failed to generate OAuth state", logger.Error(err))
		respondError(c, apperrors.ErrInternalServer)
		return
	}
	c.SetCookie("oauth_state", state, 300, "/", "", h.secureCookie, true)
	c.Redirect(http.StatusTemporaryRedirect, h.oauthSvc.GetGoogleAuthURL(state))
}

func (h *AuthHandler) GoogleCallback(c *gin.Context) {
	if err := validateOAuthState(c); err != nil {
		respondError(c, apperrors.ErrOAuthFailed)
		return
	}
	info, err := h.oauthSvc.ExchangeGoogleCode(c.Request.Context(), c.Query("code"))
	if err != nil {
		respondError(c, err)
		return
	}
	resp, err := h.authSvc.HandleOAuthLogin(c.Request.Context(), info)
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, resp)
}

func (h *AuthHandler) GithubOAuth(c *gin.Context) {
	state, err := generateState()
	if err != nil {
		h.log.Error("failed to generate OAuth state", logger.Error(err))
		respondError(c, apperrors.ErrInternalServer)
		return
	}
	c.SetCookie("oauth_state", state, 300, "/", "", h.secureCookie, true)
	c.Redirect(http.StatusTemporaryRedirect, h.oauthSvc.GetGithubAuthURL(state))
}

func (h *AuthHandler) GithubCallback(c *gin.Context) {
	if err := validateOAuthState(c); err != nil {
		respondError(c, apperrors.ErrOAuthFailed)
		return
	}
	info, err := h.oauthSvc.ExchangeGithubCode(c.Request.Context(), c.Query("code"))
	if err != nil {
		respondError(c, err)
		return
	}
	resp, err := h.authSvc.HandleOAuthLogin(c.Request.Context(), info)
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, resp)
}

func (h *AuthHandler) GetProfile(c *gin.Context) {
	rawID, exists := c.Get("userID")
	if !exists {
		respondError(c, apperrors.ErrInvalidToken)
		return
	}
	userID, err := uuid.Parse(rawID.(string))
	if err != nil {
		respondError(c, apperrors.ErrInvalidToken)
		return
	}
	user, err := h.authSvc.GetUserByID(c.Request.Context(), userID)
	if err != nil {
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, user)
}

func (h *AuthHandler) AdminDashboard(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "welcome to the admin dashboard",
		"role":    c.GetString("role"),
	})
}

func respondError(c *gin.Context, err error) {
	if appErr, ok := apperrors.As(err); ok {
		c.AbortWithStatusJSON(appErr.Code, appErr)
		return
	}
	c.AbortWithStatusJSON(http.StatusInternalServerError, apperrors.ErrInternalServer)
}

// generateState produces a cryptographically random, URL-safe state token
// for OAuth CSRF protection.
func generateState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto/rand failed: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func validateOAuthState(c *gin.Context) error {
	cookieState, _ := c.Cookie("oauth_state")
	if cookieState != c.Query("state") {
		return apperrors.ErrOAuthFailed
	}
	return nil
}
