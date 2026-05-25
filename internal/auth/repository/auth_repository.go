package repository

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/yourorg/auth-service/pkg/crypto"
	"github.com/yourorg/auth-service/pkg/database"
	apperrors "github.com/yourorg/auth-service/pkg/errors"
)

//go:generate mockgen -source=auth_repository.go -destination=../mocks/auth_repository_mock.go

type AuthRepository interface {
	CreateUser(ctx context.Context, user *database.User) error
	GetUserByEmail(ctx context.Context, email string) (*database.User, error)
	GetUserByID(ctx context.Context, id uuid.UUID) (*database.User, error)
	UpdateUser(ctx context.Context, user *database.User) error

	// OAuth
	GetOAuthAccount(ctx context.Context, provider, providerUserID string) (*database.OAuthAccount, error)
	CreateOAuthAccount(ctx context.Context, account *database.OAuthAccount) error
	UpsertOAuthAccount(ctx context.Context, account *database.OAuthAccount) error

	// --- 2.2 fix: lock-out management ---
	IncrementFailedLogins(ctx context.Context, userID uuid.UUID, lockDuration time.Duration, maxAttempts int) error
	ResetFailedLogins(ctx context.Context, userID uuid.UUID) error

	// --- 2.2 fix: email verification ---
	SetVerificationToken(ctx context.Context, userID uuid.UUID, token string) error
	VerifyEmail(ctx context.Context, token string) error
}

type authRepository struct {
	db     *gorm.DB
	// cipher is optional: nil when TOKEN_ENCRYPTION_KEY is not set (dev only).
	cipher *crypto.TokenCipher
}

// NewAuthRepository creates a repository. Pass a non-nil cipher to encrypt
// OAuth provider tokens at rest (required in production).
func NewAuthRepository(db *gorm.DB, cipher *crypto.TokenCipher) AuthRepository {
	return &authRepository{db: db, cipher: cipher}
}

func (r *authRepository) CreateUser(ctx context.Context, user *database.User) error {
	result := r.db.WithContext(ctx).Create(user)
	if result.Error != nil {
		if isDuplicateKeyError(result.Error) {
			return apperrors.ErrUserAlreadyExists
		}
		return result.Error
	}
	return nil
}

func (r *authRepository) GetUserByEmail(ctx context.Context, email string) (*database.User, error) {
	var user database.User
	result := r.db.WithContext(ctx).Where("email = ?", email).First(&user)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, apperrors.ErrUserNotFound
		}
		return nil, result.Error
	}
	return &user, nil
}

func (r *authRepository) GetUserByID(ctx context.Context, id uuid.UUID) (*database.User, error) {
	var user database.User
	result := r.db.WithContext(ctx).Where("id = ?", id).First(&user)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, apperrors.ErrUserNotFound
		}
		return nil, result.Error
	}
	return &user, nil
}

func (r *authRepository) UpdateUser(ctx context.Context, user *database.User) error {
	return r.db.WithContext(ctx).Save(user).Error
}

func (r *authRepository) GetOAuthAccount(ctx context.Context, provider, providerUserID string) (*database.OAuthAccount, error) {
	var account database.OAuthAccount
	result := r.db.WithContext(ctx).
		Preload("User").
		Where("provider = ? AND provider_user_id = ?", provider, providerUserID).
		First(&account)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil // Not found is not an error for OAuth lookup
		}
		return nil, result.Error
	}
	// Decrypt tokens after reading from DB
	if err := r.decryptOAuthTokens(&account); err != nil {
		return nil, err
	}
	return &account, nil
}

func (r *authRepository) CreateOAuthAccount(ctx context.Context, account *database.OAuthAccount) error {
	encrypted, err := r.encryptedOAuthAccount(account)
	if err != nil {
		return err
	}
	return r.db.WithContext(ctx).Create(encrypted).Error
}

func (r *authRepository) UpsertOAuthAccount(ctx context.Context, account *database.OAuthAccount) error {
	encAccess, err := r.encryptToken(account.AccessToken)
	if err != nil {
		return err
	}
	encRefresh, err := r.encryptToken(account.RefreshToken)
	if err != nil {
		return err
	}
	return r.db.WithContext(ctx).
		Where("provider = ? AND provider_user_id = ?", account.Provider, account.ProviderUserID).
		Assign(database.OAuthAccount{
			AccessToken:  encAccess,
			RefreshToken: encRefresh,
			ExpiresAt:    account.ExpiresAt,
		}).
		FirstOrCreate(account).Error
}

// encryptToken encrypts a single token string if a cipher is configured.
func (r *authRepository) encryptToken(plain string) (string, error) {
	if r.cipher == nil || plain == "" {
		return plain, nil
	}
	return r.cipher.Encrypt(plain)
}

// encryptedOAuthAccount returns a copy of account with tokens encrypted.
func (r *authRepository) encryptedOAuthAccount(account *database.OAuthAccount) (*database.OAuthAccount, error) {
	if r.cipher == nil {
		return account, nil
	}
	copy := *account
	var err error
	if copy.AccessToken, err = r.cipher.Encrypt(account.AccessToken); err != nil {
		return nil, err
	}
	if copy.RefreshToken, err = r.cipher.Encrypt(account.RefreshToken); err != nil {
		return nil, err
	}
	return &copy, nil
}

// decryptOAuthTokens decrypts tokens in-place after reading from DB.
func (r *authRepository) decryptOAuthTokens(account *database.OAuthAccount) error {
	if r.cipher == nil {
		return nil
	}
	var err error
	if account.AccessToken, err = r.cipher.Decrypt(account.AccessToken); err != nil {
		return err
	}
	if account.RefreshToken, err = r.cipher.Decrypt(account.RefreshToken); err != nil {
		return err
	}
	return nil
}

// IncrementFailedLogins increments the failed login counter.
// If maxAttempts is reached, LockedUntil is set to now+lockDuration.
// --- 2.2 fix: account lock-out ---
func (r *authRepository) IncrementFailedLogins(ctx context.Context, userID uuid.UUID, lockDuration time.Duration, maxAttempts int) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var user database.User
		if err := tx.Where("id = ?", userID).First(&user).Error; err != nil {
			return err
		}
		user.FailedLoginAttempts++
		if user.FailedLoginAttempts >= maxAttempts {
			lockUntil := time.Now().Add(lockDuration)
			user.LockedUntil = &lockUntil
		}
		return tx.Save(&user).Error
	})
}

// ResetFailedLogins clears the counter and lock after a successful login.
// --- 2.2 fix: account lock-out ---
func (r *authRepository) ResetFailedLogins(ctx context.Context, userID uuid.UUID) error {
	return r.db.WithContext(ctx).Model(&database.User{}).
		Where("id = ?", userID).
		Updates(map[string]interface{}{
			"failed_login_attempts": 0,
			"locked_until":          nil,
		}).Error
}

// SetVerificationToken stores a verification token for email verification.
// --- 2.2 fix: email verification ---
func (r *authRepository) SetVerificationToken(ctx context.Context, userID uuid.UUID, token string) error {
	return r.db.WithContext(ctx).Model(&database.User{}).
		Where("id = ?", userID).
		Update("verification_token", token).Error
}

// VerifyEmail marks the user's email as verified if the token matches.
// --- 2.2 fix: email verification ---
func (r *authRepository) VerifyEmail(ctx context.Context, token string) error {
	now := time.Now()
	result := r.db.WithContext(ctx).Model(&database.User{}).
		Where("verification_token = ? AND email_verified = false", token).
		Updates(map[string]interface{}{
			"email_verified":     true,
			"verification_token": "",
			"is_active":          true,
			"verified_at":        now,
		})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return apperrors.WithDetail(apperrors.ErrBadRequest, "invalid or already-used verification token")
	}
	return nil
}

// isDuplicateKeyError detects PostgreSQL unique constraint violations.
func isDuplicateKeyError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "duplicate key") || strings.Contains(msg, "unique constraint")
}
