package cxf

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
)

var (
	// ErrInvalidIdentifierLength indicates an identifier exceeds 64 bytes decoded.
	ErrInvalidIdentifierLength = errors.New("identifier exceeds 64 bytes")
	// ErrEmptyLength indicates a non-positive length was requested.
	ErrEmptyLength = errors.New("length must be positive")
)

// EncodeBase64URL encodes data using unpadded base64url.
func EncodeBase64URL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// DecodeBase64URL decodes unpadded base64url data.
func DecodeBase64URL(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// ValidateBase64URL checks whether a string is valid unpadded base64url.
func ValidateBase64URL(s string) error {
	_, err := DecodeBase64URL(s)
	return err
}

// EncodeBase32 encodes data using unpadded Base32 (RFC4648).
func EncodeBase32(data []byte) string {
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	return enc.EncodeToString(data)
}

// DecodeBase32 decodes unpadded Base32 (RFC4648).
func DecodeBase32(s string) ([]byte, error) {
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	return enc.DecodeString(s)
}

// ValidateBase32 checks whether a string is valid unpadded Base32.
func ValidateBase32(s string) error {
	_, err := DecodeBase32(s)
	return err
}

// GenerateIdentifier returns a random identifier of the requested byte length,
// encoded as unpadded base64url. The decoded identifier length must be >0 and ≤64 bytes.
func GenerateIdentifier(length int) (string, error) {
	if length <= 0 {
		return "", ErrEmptyLength
	}
	if length > 64 {
		// Prevent generating IDs longer than the spec allows when decoded.
		return "", ErrInvalidIdentifierLength
	}

	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	return EncodeBase64URL(buf), nil
}

// ValidateIdentifier ensures the identifier is valid base64url and ≤64 bytes when decoded.
func ValidateIdentifier(id string) error {
	decoded, err := DecodeBase64URL(id)
	if err != nil {
		return err
	}
	if len(decoded) > 64 {
		return ErrInvalidIdentifierLength
	}
	return nil
}

// GenerateCredentialID is an alias for GenerateIdentifier.
func GenerateCredentialID(length int) (string, error) {
	return GenerateIdentifier(length)
}

// GenerateUserID is an alias for GenerateIdentifier.
func GenerateUserID(length int) (string, error) {
	return GenerateIdentifier(length)
}
