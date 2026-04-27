package validator_test

import (
	"testing"

	"github.com/yourorg/auth-service/pkg/validator"
)

func TestValidateEmail(t *testing.T) {
	cases := []struct {
		email string
		valid bool
	}{
		{"user@example.com", true},
		{"user+tag@sub.domain.io", true},
		{"UPPER@EXAMPLE.COM", true},
		{"notanemail", false},
		{"@nodomain.com", false},
		{"user@", false},
		{"", false},
		{"user @example.com", false},
	}

	for _, tc := range cases {
		got := validator.ValidateEmail(tc.email)
		if got != tc.valid {
			t.Errorf("ValidateEmail(%q) = %v, want %v", tc.email, got, tc.valid)
		}
	}
}

func TestValidatePassword(t *testing.T) {
	cases := []struct {
		password string
		valid    bool
	}{
		{"Password1", true},
		{"Abcdefg1!", true},
		{"short1A", false},    // too short
		{"alllowercase1", false}, // no upper
		{"ALLUPPERCASE1", false}, // no lower
		{"NoDigitsHere", false},  // no digit
		{"", false},
	}

	for _, tc := range cases {
		ok, _ := validator.ValidatePassword(tc.password)
		if ok != tc.valid {
			t.Errorf("ValidatePassword(%q) = %v, want %v", tc.password, ok, tc.valid)
		}
	}
}

func TestSanitizeEmail(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"  USER@EXAMPLE.COM  ", "user@example.com"},
		{"Test@Test.Org", "test@test.org"},
		{"already@clean.com", "already@clean.com"},
	}

	for _, tc := range cases {
		got := validator.SanitizeEmail(tc.input)
		if got != tc.expected {
			t.Errorf("SanitizeEmail(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}
