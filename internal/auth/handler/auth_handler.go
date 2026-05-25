package handler

import (
	"crypto/rand"
	"crypto/subtle"
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
	secureCookie bool
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

	// --- 2.2 fix: email verification ---
	// Account is inactive until verified. Tokens are nil in the response.
	// TODO: dispatch verification email here (plug in your email provider).
	// The verification link format: GET /api/v1/verify-email?token=<token>
	// For now we log it so devs can test locally without an email provider.
	h.log.Info("verification email needed",
		logger.String("email", resp.User.Email),
		// In production, remove this log and send the actual email.
	)

	c.JSON(http.StatusCreated, gin.H{
		"user":    resp.User,
		"message": "account created — please check your email to verify your address before logging in",
	})
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

// VerifyEmail handles GET /api/v1/verify-email?token=...
// --- 2.2 fix: email verification endpoint ---
func (h *AuthHandler) VerifyEmail(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		respondError(c, apperrors.WithDetail(apperrors.ErrBadRequest, "token query param is required"))
		return
	}
	if err := h.authSvc.VerifyEmail(c.Request.Context(), token); err != nil {
		h.log.Warn("email verification failed", logger.Error(err))
		respondError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "email verified — you can now log in"})
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
		// --- 2.2 fix: surface explicit linking requirement ---
		if appErr, ok := apperrors.As(err); ok && appErr == apperrors.ErrOAuthLinkRequired {
			c.AbortWithStatusJSON(http.StatusConflict, gin.H{
				"message":       appErr.Message,
				"link_required": true,
				// link_token would be issued here once Phase 2 linking flow is built
			})
			return
		}
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
		// --- 2.2 fix: surface explicit linking requirement ---
		if appErr, ok := apperrors.As(err); ok && appErr == apperrors.ErrOAuthLinkRequired {
			c.AbortWithStatusJSON(http.StatusConflict, gin.H{
				"message":       appErr.Message,
				"link_required": true,
			})
			return
		}
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

func generateState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto/rand failed: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// validateOAuthState uses constant-time comparison to prevent timing oracle attacks.
func validateOAuthState(c *gin.Context) error {
	cookieState, err := c.Cookie("oauth_state")
	if err != nil || cookieState == "" {
		return apperrors.ErrOAuthFailed
	}
	queryState := c.Query("state")
	// subtle.ConstantTimeCompare guards against timing side-channel on the CSRF token.
	if subtle.ConstantTimeCompare([]byte(cookieState), []byte(queryState)) != 1 {
		return apperrors.ErrOAuthFailed
	}
	return nil
}
