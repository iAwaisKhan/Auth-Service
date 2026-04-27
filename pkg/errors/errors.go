package errors

import (
	"errors"
	"net/http"
)

// AppError is a structured application error
type AppError struct {
	Code    int    `json:"-"`
	Message string `json:"message"`
	Detail  string `json:"detail,omitempty"`
}

func (e *AppError) Error() string {
	return e.Message
}

// Sentinel errors
var (
	ErrInvalidCredentials = &AppError{Code: http.StatusUnauthorized, Message: "invalid email or password"}
	ErrUserNotFound       = &AppError{Code: http.StatusNotFound, Message: "user not found"}
	ErrUserAlreadyExists  = &AppError{Code: http.StatusConflict, Message: "user with this email already exists"}
	ErrInvalidToken       = &AppError{Code: http.StatusUnauthorized, Message: "invalid or expired token"}
	ErrTokenExpired       = &AppError{Code: http.StatusUnauthorized, Message: "token has expired"}
	ErrForbidden          = &AppError{Code: http.StatusForbidden, Message: "you do not have permission to access this resource"}
	ErrInternalServer     = &AppError{Code: http.StatusInternalServerError, Message: "internal server error"}
	ErrBadRequest         = &AppError{Code: http.StatusBadRequest, Message: "bad request"}
	ErrAccountInactive    = &AppError{Code: http.StatusForbidden, Message: "account is inactive"}
	ErrOAuthFailed        = &AppError{Code: http.StatusBadGateway, Message: "oauth provider error"}
)

// New creates a new AppError
func New(code int, message string) *AppError {
	return &AppError{Code: code, Message: message}
}

// WithDetail adds detail to an error copy
func WithDetail(err *AppError, detail string) *AppError {
	return &AppError{Code: err.Code, Message: err.Message, Detail: detail}
}

// As unwraps to AppError
func As(err error) (*AppError, bool) {
	var appErr *AppError
	ok := errors.As(err, &appErr)
	return appErr, ok
}
