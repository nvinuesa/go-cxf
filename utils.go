package cxf

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// GenerateCredentialID generates a random credential ID.
// The ID is base64url encoded and has the specified length in bytes before encoding.
func GenerateCredentialID(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("length must be positive")
	}

	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// GenerateUserID generates a random user ID.
// The ID is base64url encoded and has the specified length in bytes before encoding.
func GenerateUserID(length int) (string, error) {
	return GenerateCredentialID(length)
}

// EncodeBase64URL encodes data to base64url format (without padding).
func EncodeBase64URL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// DecodeBase64URL decodes base64url encoded data.
func DecodeBase64URL(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// ValidateBase64URL validates if a string is valid base64url encoding.
func ValidateBase64URL(s string) error {
	_, err := DecodeBase64URL(s)
	return err
}
