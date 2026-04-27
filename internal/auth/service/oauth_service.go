package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"

	"github.com/yourorg/auth-service/pkg/config"
	apperrors "github.com/yourorg/auth-service/pkg/errors"
)

type OAuthService interface {
	GetGoogleAuthURL(state string) string
	GetGithubAuthURL(state string) string
	ExchangeGoogleCode(ctx context.Context, code string) (*OAuthUserInfo, error)
	ExchangeGithubCode(ctx context.Context, code string) (*OAuthUserInfo, error)
}

type oauthService struct {
	googleConfig *oauth2.Config
	githubConfig *oauth2.Config
}

func NewOAuthService(cfg config.OAuthConfig) OAuthService {
	googleConfig := &oauth2.Config{
		ClientID:     cfg.GoogleClientID,
		ClientSecret: cfg.GoogleClientSecret,
		RedirectURL:  cfg.GoogleRedirectURL,
		Scopes:       []string{"openid", "email", "profile"},
		Endpoint:     google.Endpoint,
	}

	githubConfig := &oauth2.Config{
		ClientID:     cfg.GithubClientID,
		ClientSecret: cfg.GithubClientSecret,
		RedirectURL:  cfg.GithubRedirectURL,
		Scopes:       []string{"user:email", "read:user"},
		Endpoint:     github.Endpoint,
	}

	return &oauthService{
		googleConfig: googleConfig,
		githubConfig: githubConfig,
	}
}

func (s *oauthService) GetGoogleAuthURL(state string) string {
	return s.googleConfig.AuthCodeURL(state, oauth2.AccessTypeOffline)
}

func (s *oauthService) GetGithubAuthURL(state string) string {
	return s.githubConfig.AuthCodeURL(state)
}

func (s *oauthService) ExchangeGoogleCode(ctx context.Context, code string) (*OAuthUserInfo, error) {
	token, err := s.googleConfig.Exchange(ctx, code)
	if err != nil {
		return nil, apperrors.ErrOAuthFailed
	}

	client := s.googleConfig.Client(ctx, token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		return nil, apperrors.ErrOAuthFailed
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, apperrors.ErrOAuthFailed
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, apperrors.ErrOAuthFailed
	}

	var googleUser struct {
		Sub     string `json:"sub"`
		Email   string `json:"email"`
		Name    string `json:"name"`
		Picture string `json:"picture"`
	}
	if err := json.Unmarshal(body, &googleUser); err != nil {
		return nil, apperrors.ErrOAuthFailed
	}

	// Capture token expiry only if the provider set one (zero means no expiry)
	var expiresAt *time.Time
	if !token.Expiry.IsZero() {
		t := token.Expiry
		expiresAt = &t
	}

	return &OAuthUserInfo{
		ProviderUserID:       googleUser.Sub,
		Email:                googleUser.Email,
		Name:                 googleUser.Name,
		AvatarURL:            googleUser.Picture,
		Provider:             "google",
		ProviderToken:        token.AccessToken,
		ProviderRefreshToken: token.RefreshToken,
		ProviderTokenExpiry:  expiresAt,
	}, nil
}

func (s *oauthService) ExchangeGithubCode(ctx context.Context, code string) (*OAuthUserInfo, error) {
	token, err := s.githubConfig.Exchange(ctx, code)
	if err != nil {
		return nil, apperrors.ErrOAuthFailed
	}

	client := s.githubConfig.Client(ctx, token)

	// Fetch user profile
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		return nil, apperrors.ErrOAuthFailed
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, apperrors.ErrOAuthFailed
	}

	var ghUser struct {
		ID        int    `json:"id"`
		Login     string `json:"login"`
		Name      string `json:"name"`
		Email     string `json:"email"`
		AvatarURL string `json:"avatar_url"`
	}
	if err := json.Unmarshal(body, &ghUser); err != nil {
		return nil, apperrors.ErrOAuthFailed
	}

	// GitHub may not expose email — fetch primary email explicitly
	email := ghUser.Email
	if email == "" {
		email, err = s.fetchGithubPrimaryEmail(client)
		if err != nil || email == "" {
			return nil, apperrors.WithDetail(apperrors.ErrOAuthFailed, "could not retrieve email from GitHub")
		}
	}

	name := ghUser.Name
	if name == "" {
		name = ghUser.Login
	}

	// GitHub personal access tokens don't expire; only capture expiry when set.
	var expiresAt *time.Time
	if !token.Expiry.IsZero() {
		t := token.Expiry
		expiresAt = &t
	}

	return &OAuthUserInfo{
		ProviderUserID:       fmt.Sprintf("%d", ghUser.ID),
		Email:                email,
		Name:                 name,
		AvatarURL:            ghUser.AvatarURL,
		Provider:             "github",
		ProviderToken:        token.AccessToken,
		ProviderRefreshToken: token.RefreshToken,
		ProviderTokenExpiry:  expiresAt,
	}, nil
}

func (s *oauthService) fetchGithubPrimaryEmail(client *http.Client) (string, error) {
	resp, err := client.Get("https://api.github.com/user/emails")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.Unmarshal(body, &emails); err != nil {
		return "", err
	}

	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, nil
		}
	}
	return "", nil
}
