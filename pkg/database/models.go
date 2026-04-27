package database

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Provider constants
const (
	ProviderLocal  = "local"
	ProviderGoogle = "google"
	ProviderGithub = "github"
)

// Role constants
const (
	RoleUser  = "user"
	RoleAdmin = "admin"
)

// User is the core user model persisted in PostgreSQL
type User struct {
	ID        uuid.UUID      `gorm:"type:uuid;primaryKey"                    json:"id"`
	Email     string         `gorm:"type:varchar(255);uniqueIndex;not null"  json:"email"`
	Password  string         `gorm:"type:varchar(255)"                       json:"-"`
	Provider  string         `gorm:"type:varchar(50);not null;default:local" json:"provider"`
	Role      string         `gorm:"type:varchar(50);not null;default:user"  json:"role"`
	Name      string         `gorm:"type:varchar(255)"                       json:"name"`
	AvatarURL string         `gorm:"type:varchar(512)"                       json:"avatar_url,omitempty"`
	IsActive  bool           `gorm:"not null;default:true"                   json:"is_active"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index"                                   json:"-"`
}

// BeforeCreate sets UUID before inserting a new User record
func (u *User) BeforeCreate(tx *gorm.DB) error {
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	if u.Role == "" {
		u.Role = RoleUser
	}
	if u.Provider == "" {
		u.Provider = ProviderLocal
	}
	return nil
}

// OAuthAccount stores OAuth provider tokens linked to a User
type OAuthAccount struct {
	ID             uuid.UUID `gorm:"type:uuid;primaryKey"                          json:"id"`
	UserID         uuid.UUID `gorm:"type:uuid;not null;index"                      json:"user_id"`
	Provider       string    `gorm:"type:varchar(50);not null"                     json:"provider"`
	ProviderUserID string    `gorm:"type:varchar(255);not null"                    json:"provider_user_id"`
	AccessToken    string    `gorm:"type:text"                                     json:"-"`
	RefreshToken   string    `gorm:"type:text"                                     json:"-"`
	ExpiresAt      *time.Time `                                                    json:"expires_at,omitempty"`
	CreatedAt      time.Time `                                                    json:"created_at"`
	UpdatedAt      time.Time `                                                    json:"updated_at"`

	User User `gorm:"foreignKey:UserID" json:"-"`
}

func (o *OAuthAccount) BeforeCreate(tx *gorm.DB) error {
	if o.ID == uuid.Nil {
		o.ID = uuid.New()
	}
	return nil
}
