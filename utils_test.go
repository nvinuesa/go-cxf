package cxf

import (
	"encoding/base32"
	"encoding/base64"
	"testing"
)

func TestGenerateIdentifier(t *testing.T) {
	tests := []struct {
		name      string
		length    int
		wantErr   error
		expectLen int
	}{
		{name: "16 bytes", length: 16, wantErr: nil, expectLen: 16},
		{name: "32 bytes", length: 32, wantErr: nil, expectLen: 32},
		{name: "64 bytes max", length: 64, wantErr: nil, expectLen: 64},
		{name: "zero length", length: 0, wantErr: ErrEmptyLength},
		{name: "negative length", length: -1, wantErr: ErrEmptyLength},
		{name: "exceeds max", length: 65, wantErr: ErrInvalidIdentifierLength},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := GenerateIdentifier(tt.length)
			if tt.wantErr != nil {
				if err == nil || err.Error() != tt.wantErr.Error() {
					t.Fatalf("GenerateIdentifier() error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("GenerateIdentifier() error = %v, want nil", err)
			}
			if id == "" {
				t.Fatalf("expected non-empty identifier")
			}
			decoded, err := DecodeBase64URL(id)
			if err != nil {
				t.Fatalf("decoded identifier invalid base64url: %v", err)
			}
			if len(decoded) != tt.expectLen {
				t.Fatalf("decoded length = %d, want %d", len(decoded), tt.expectLen)
			}
		})
	}
}

func TestValidateIdentifier(t *testing.T) {
	validID, _ := GenerateIdentifier(16)
	tooLong := EncodeBase64URL(make([]byte, 65))
	badB64 := "not@valid#b64"

	tests := []struct {
		name    string
		id      string
		wantErr bool
	}{
		{name: "valid", id: validID, wantErr: false},
		{name: "too long", id: tooLong, wantErr: true},
		{name: "invalid base64", id: badB64, wantErr: true},
		{name: "empty", id: "", wantErr: false}, // empty decodes to zero-length, allowed by ValidateIdentifier if caller passes it
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateIdentifier(tt.id)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateIdentifier(%q) error = %v, wantErr %v", tt.id, err, tt.wantErr)
			}
		})
	}
}

func TestBase64URLHelpers(t *testing.T) {
	raw := []byte("hello-world")
	encoded := EncodeBase64URL(raw)

	if _, err := DecodeBase64URL(encoded); err != nil {
		t.Fatalf("DecodeBase64URL(%q) error = %v", encoded, err)
	}

	if err := ValidateBase64URL(encoded); err != nil {
		t.Fatalf("ValidateBase64URL(%q) error = %v", encoded, err)
	}

	if err := ValidateBase64URL(encoded + "==="); err == nil {
		t.Fatalf("expected error for padded base64url input")
	}
}

func TestBase32Helpers(t *testing.T) {
	raw := []byte("hello-base32")
	encoded := EncodeBase32(raw)

	// Ensure we use unpadded encoding
	if encoded[len(encoded)-1] == '=' {
		t.Fatalf("expected no padding in Base32 encoding, got %q", encoded)
	}

	decoded, err := DecodeBase32(encoded)
	if err != nil {
		t.Fatalf("DecodeBase32 error: %v", err)
	}
	if string(decoded) != string(raw) {
		t.Fatalf("DecodeBase32 roundtrip mismatch: got %q, want %q", decoded, raw)
	}

	if err := ValidateBase32(encoded); err != nil {
		t.Fatalf("ValidateBase32(%q) error = %v", encoded, err)
	}

	// Invalid character
	if err := ValidateBase32(encoded + "!"); err == nil {
		t.Fatalf("expected error for invalid Base32 input")
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	vectors := [][]byte{
		[]byte(""),
		[]byte("abc123"),
		[]byte{0x00, 0xFF, 0x10, 0x20},
		make([]byte, 128),
	}

	for i, vec := range vectors {
		enc := EncodeBase64URL(vec)
		dec, err := DecodeBase64URL(enc)
		if err != nil {
			t.Fatalf("case %d: DecodeBase64URL error = %v", i, err)
		}
		if string(dec) != string(vec) {
			t.Fatalf("case %d: roundtrip mismatch got %v want %v", i, dec, vec)
		}
	}
}

func TestBase32ReferenceEncoding(t *testing.T) {
	// Cross-check against stdlib with NoPadding to ensure deterministic encoding
	raw := []byte("test-data-123")
	ref := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	got := EncodeBase32(raw)
	if got != ref {
		t.Fatalf("EncodeBase32 mismatch: got %q, want %q", got, ref)
	}
}

func TestBase64URLReferenceEncoding(t *testing.T) {
	raw := []byte("test-data-b64")
	ref := base64.RawURLEncoding.EncodeToString(raw)
	got := EncodeBase64URL(raw)
	if got != ref {
		t.Fatalf("EncodeBase64URL mismatch: got %q, want %q", got, ref)
	}
}

func TestGenerateCredentialIDAlias(t *testing.T) {
	id, err := GenerateCredentialID(16)
	if err != nil {
		t.Fatalf("GenerateCredentialID() error = %v, want nil", err)
	}
	if id == "" {
		t.Fatalf("expected non-empty identifier")
	}
	decoded, err := DecodeBase64URL(id)
	if err != nil {
		t.Fatalf("decoded credential id invalid base64url: %v", err)
	}
	if len(decoded) != 16 {
		t.Fatalf("decoded length = %d, want %d", len(decoded), 16)
	}
}

func TestGenerateUserIDAlias(t *testing.T) {
	id, err := GenerateUserID(16)
	if err != nil {
		t.Fatalf("GenerateUserID() error = %v, want nil", err)
	}
	if id == "" {
		t.Fatalf("expected non-empty identifier")
	}
	decoded, err := DecodeBase64URL(id)
	if err != nil {
		t.Fatalf("decoded user id invalid base64url: %v", err)
	}
	if len(decoded) != 16 {
		t.Fatalf("decoded length = %d, want %d", len(decoded), 16)
	}
}
