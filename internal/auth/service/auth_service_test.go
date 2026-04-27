package service_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	authRepo "github.com/yourorg/auth-service/internal/auth/repository"
	"github.com/yourorg/auth-service/internal/auth/service"
	"github.com/yourorg/auth-service/pkg/database"
	apperrors "github.com/yourorg/auth-service/pkg/errors"
)

// ── In-memory fake repository ─────────────────────────────────────────────────

type fakeAuthRepo struct {
	users        map[string]*database.User
	oauthAccounts map[string]*database.OAuthAccount
}

func newFakeRepo() authRepo.AuthRepository {
	return &fakeAuthRepo{
		users:        make(map[string]*database.User),
		oauthAccounts: make(map[string]*database.OAuthAccount),
	}
}

func (f *fakeAuthRepo) CreateUser(_ context.Context, user *database.User) error {
	if _, exists := f.users[user.Email]; exists {
		return apperrors.ErrUserAlreadyExists
	}
	if user.ID == uuid.Nil {
		user.ID = uuid.New()
	}
	if user.Role == "" {
		user.Role = database.RoleUser
	}
	// Mirror the GORM model's `default:true` — new users are active by default.
	user.IsActive = true
	f.users[user.Email] = user
	return nil
}

func (f *fakeAuthRepo) GetUserByEmail(_ context.Context, email string) (*database.User, error) {
	if u, ok := f.users[email]; ok {
		return u, nil
	}
	return nil, apperrors.ErrUserNotFound
}

func (f *fakeAuthRepo) GetUserByID(_ context.Context, id uuid.UUID) (*database.User, error) {
	for _, u := range f.users {
		if u.ID == id {
			return u, nil
		}
	}
	return nil, apperrors.ErrUserNotFound
}

func (f *fakeAuthRepo) UpdateUser(_ context.Context, user *database.User) error {
	f.users[user.Email] = user
	return nil
}

func (f *fakeAuthRepo) GetOAuthAccount(_ context.Context, provider, providerUserID string) (*database.OAuthAccount, error) {
	key := provider + ":" + providerUserID
	if a, ok := f.oauthAccounts[key]; ok {
		return a, nil
	}
	return nil, nil
}

func (f *fakeAuthRepo) CreateOAuthAccount(_ context.Context, account *database.OAuthAccount) error {
	key := account.Provider + ":" + account.ProviderUserID
	f.oauthAccounts[key] = account
	return nil
}

func (f *fakeAuthRepo) UpsertOAuthAccount(_ context.Context, account *database.OAuthAccount) error {
	key := account.Provider + ":" + account.ProviderUserID
	f.oauthAccounts[key] = account
	return nil
}

// ── Fake token service ─────────────────────────────────────────────────────────

type fakeTokenService struct{}

func (f *fakeTokenService) GenerateTokenPair(_ context.Context, userID uuid.UUID, email, role string) (*service.TokenPair, error) {
	return &service.TokenPair{
		AccessToken:  "fake-access-" + userID.String(),
		RefreshToken: "fake-refresh-" + userID.String(),
		ExpiresIn:    900,
	}, nil
}

func (f *fakeTokenService) ValidateAccessToken(token string) (*service.Claims, error) {
	return nil, nil
}

func (f *fakeTokenService) ValidateRefreshToken(_ context.Context, token string) (*service.Claims, error) {
	return nil, nil
}

func (f *fakeTokenService) RevokeRefreshToken(_ context.Context, token string) error {
	return nil
}

func (f *fakeTokenService) RotateRefreshToken(_ context.Context, token string) (*service.TokenPair, error) {
	return &service.TokenPair{
		AccessToken:  "new-access",
		RefreshToken: "new-refresh",
		ExpiresIn:    900,
	}, nil
}

// ── Tests ─────────────────────────────────────────────────────────────────────

func newTestAuthService() service.AuthService {
	return service.NewAuthService(newFakeRepo(), &fakeTokenService{})
}

func TestSignup_Success(t *testing.T) {
	svc := newTestAuthService()
	resp, err := svc.Signup(context.Background(), &service.SignupRequest{
		Name:     "Alice",
		Email:    "alice@example.com",
		Password: "Password1",
	})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if resp.User.Email != "alice@example.com" {
		t.Errorf("expected email alice@example.com, got %s", resp.User.Email)
	}
	if resp.Tokens == nil {
		t.Error("expected tokens, got nil")
	}
}

func TestSignup_DuplicateEmail(t *testing.T) {
	svc := newTestAuthService()
	req := &service.SignupRequest{Name: "Alice", Email: "alice@example.com", Password: "Password1"}
	_, _ = svc.Signup(context.Background(), req)
	_, err := svc.Signup(context.Background(), req)
	if err != apperrors.ErrUserAlreadyExists {
		t.Errorf("expected ErrUserAlreadyExists, got: %v", err)
	}
}

func TestSignup_WeakPassword(t *testing.T) {
	svc := newTestAuthService()
	_, err := svc.Signup(context.Background(), &service.SignupRequest{
		Name:     "Bob",
		Email:    "bob@example.com",
		Password: "weak",
	})
	if err == nil {
		t.Error("expected error for weak password")
	}
}

func TestSignup_InvalidEmail(t *testing.T) {
	svc := newTestAuthService()
	_, err := svc.Signup(context.Background(), &service.SignupRequest{
		Name:     "Carol",
		Email:    "not-an-email",
		Password: "Password1",
	})
	if err == nil {
		t.Error("expected error for invalid email")
	}
}

func TestLogin_Success(t *testing.T) {
	svc := newTestAuthService()
	_, _ = svc.Signup(context.Background(), &service.SignupRequest{
		Name:     "Dave",
		Email:    "dave@example.com",
		Password: "Password1",
	})

	resp, err := svc.Login(context.Background(), &service.LoginRequest{
		Email:    "dave@example.com",
		Password: "Password1",
	})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if resp.User.Email != "dave@example.com" {
		t.Errorf("wrong email in response")
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	svc := newTestAuthService()
	_, _ = svc.Signup(context.Background(), &service.SignupRequest{
		Name:     "Eve",
		Email:    "eve@example.com",
		Password: "Password1",
	})

	_, err := svc.Login(context.Background(), &service.LoginRequest{
		Email:    "eve@example.com",
		Password: "WrongPass1",
	})
	if err != apperrors.ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials, got: %v", err)
	}
}

func TestLogin_UserNotFound(t *testing.T) {
	svc := newTestAuthService()
	_, err := svc.Login(context.Background(), &service.LoginRequest{
		Email:    "ghost@example.com",
		Password: "Password1",
	})
	if err != apperrors.ErrInvalidCredentials {
		t.Errorf("expected ErrInvalidCredentials, got: %v", err)
	}
}

func TestOAuthLogin_NewUser(t *testing.T) {
	svc := newTestAuthService()
	resp, err := svc.HandleOAuthLogin(context.Background(), &service.OAuthUserInfo{
		ProviderUserID: "google-123",
		Email:          "frank@gmail.com",
		Name:           "Frank",
		Provider:       "google",
	})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if resp.User.Provider != "google" {
		t.Errorf("expected provider google, got %s", resp.User.Provider)
	}
}

func TestOAuthLogin_ExistingEmailLink(t *testing.T) {
	svc := newTestAuthService()

	// Pre-create a local user with the same email
	_, _ = svc.Signup(context.Background(), &service.SignupRequest{
		Name:     "Grace",
		Email:    "grace@gmail.com",
		Password: "Password1",
	})

	// OAuth login should link to existing account
	resp, err := svc.HandleOAuthLogin(context.Background(), &service.OAuthUserInfo{
		ProviderUserID: "github-456",
		Email:          "grace@gmail.com",
		Name:           "Grace",
		Provider:       "github",
	})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if resp.User.Email != "grace@gmail.com" {
		t.Errorf("expected grace@gmail.com, got %s", resp.User.Email)
	}
}
