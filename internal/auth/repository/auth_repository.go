package repository

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"gorm.io/gorm"

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
}

type authRepository struct {
	db *gorm.DB
}

func NewAuthRepository(db *gorm.DB) AuthRepository {
	return &authRepository{db: db}
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
	// Note: GORM's soft-delete automatically appends `deleted_at IS NULL`
	// for models embedding gorm.DeletedAt — no manual filter needed.
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
	// GORM handles soft-delete filtering automatically.
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
	return &account, nil
}

func (r *authRepository) CreateOAuthAccount(ctx context.Context, account *database.OAuthAccount) error {
	return r.db.WithContext(ctx).Create(account).Error
}

func (r *authRepository) UpsertOAuthAccount(ctx context.Context, account *database.OAuthAccount) error {
	return r.db.WithContext(ctx).
		Where("provider = ? AND provider_user_id = ?", account.Provider, account.ProviderUserID).
		Assign(database.OAuthAccount{
			AccessToken:  account.AccessToken,
			RefreshToken: account.RefreshToken,
			ExpiresAt:    account.ExpiresAt,
		}).
		FirstOrCreate(account).Error
}

// isDuplicateKeyError detects PostgreSQL unique constraint violations.
func isDuplicateKeyError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "duplicate key") || strings.Contains(msg, "unique constraint")
}
