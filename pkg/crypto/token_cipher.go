// Package crypto provides AES-256-GCM encryption for sensitive values stored at rest.
// Used to encrypt OAuth provider access/refresh tokens before writing to the database.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// TokenCipher encrypts and decrypts short strings (OAuth tokens) using AES-256-GCM.
// The key must be exactly 32 bytes (256 bits).
type TokenCipher struct {
	gcm cipher.AEAD
}

// NewTokenCipher creates a cipher from a 32-byte key.
// Provide via TOKEN_ENCRYPTION_KEY env var (32 random bytes, base64-encoded).
func NewTokenCipher(key []byte) (*TokenCipher, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("token cipher: key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("token cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("token cipher: %w", err)
	}
	return &TokenCipher{gcm: gcm}, nil
}

// Encrypt encrypts plaintext and returns a base64url-encoded ciphertext (nonce‖ciphertext).
// Returns "" unchanged for empty strings so nil/empty tokens round-trip cleanly.
func (c *TokenCipher) Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}
	nonce := make([]byte, c.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("token cipher encrypt: nonce generation: %w", err)
	}
	sealed := c.gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.URLEncoding.EncodeToString(sealed), nil
}

// Decrypt decodes and decrypts a value produced by Encrypt.
// Returns "" unchanged for empty strings.
func (c *TokenCipher) Decrypt(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}
	data, err := base64.URLEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("token cipher decrypt: base64: %w", err)
	}
	nonceSize := c.gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("token cipher decrypt: ciphertext too short")
	}
	nonce, ct := data[:nonceSize], data[nonceSize:]
	plain, err := c.gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", fmt.Errorf("token cipher decrypt: %w", err)
	}
	return string(plain), nil
}
