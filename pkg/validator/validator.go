package validator

import (
	"regexp"
	"strings"
	"unicode"
)

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

// ValidateEmail returns true if email is valid
func ValidateEmail(email string) bool {
	return emailRegex.MatchString(strings.ToLower(strings.TrimSpace(email)))
}

// ValidatePassword checks minimum password requirements
// At least 8 chars, 1 upper, 1 lower, 1 digit
func ValidatePassword(password string) (bool, string) {
	if len(password) < 8 {
		return false, "password must be at least 8 characters"
	}

	var hasUpper, hasLower, hasDigit bool
	for _, ch := range password {
		switch {
		case unicode.IsUpper(ch):
			hasUpper = true
		case unicode.IsLower(ch):
			hasLower = true
		case unicode.IsDigit(ch):
			hasDigit = true
		}
	}

	if !hasUpper {
		return false, "password must contain at least one uppercase letter"
	}
	if !hasLower {
		return false, "password must contain at least one lowercase letter"
	}
	if !hasDigit {
		return false, "password must contain at least one digit"
	}

	return true, ""
}

// SanitizeString trims and lowercases a string
func SanitizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
