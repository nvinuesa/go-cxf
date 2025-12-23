package cxf

import (
	"encoding/base64"
	"testing"
)

func TestGenerateCredentialID(t *testing.T) {
	tests := []struct {
		name    string
		length  int
		wantErr bool
	}{
		{
			name:    "valid length 16",
			length:  16,
			wantErr: false,
		},
		{
			name:    "valid length 32",
			length:  32,
			wantErr: false,
		},
		{
			name:    "valid length 64",
			length:  64,
			wantErr: false,
		},
		{
			name:    "zero length",
			length:  0,
			wantErr: true,
		},
		{
			name:    "negative length",
			length:  -1,
			wantErr: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := GenerateCredentialID(tt.length)
			
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateCredentialID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			
			if !tt.wantErr {
				if id == "" {
					t.Error("Expected non-empty credential ID")
				}
				
				// Verify it's valid base64url
				if err := ValidateBase64URL(id); err != nil {
					t.Errorf("Generated ID is not valid base64url: %v", err)
				}
				
				// Verify decoded length matches expected
				decoded, err := DecodeBase64URL(id)
				if err != nil {
					t.Errorf("Failed to decode generated ID: %v", err)
				}
				
				if len(decoded) != tt.length {
					t.Errorf("Decoded length = %d, want %d", len(decoded), tt.length)
				}
			}
		})
	}
}

func TestGenerateUserID(t *testing.T) {
	id1, err := GenerateUserID(16)
	if err != nil {
		t.Fatalf("GenerateUserID() error = %v", err)
	}
	
	id2, err := GenerateUserID(16)
	if err != nil {
		t.Fatalf("GenerateUserID() error = %v", err)
	}
	
	// IDs should be unique
	if id1 == id2 {
		t.Error("Expected unique user IDs")
	}
	
	// Both should be valid base64url
	if err := ValidateBase64URL(id1); err != nil {
		t.Errorf("ID1 is not valid base64url: %v", err)
	}
	
	if err := ValidateBase64URL(id2); err != nil {
		t.Errorf("ID2 is not valid base64url: %v", err)
	}
}

func TestEncodeBase64URL(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{
			name:  "empty",
			input: []byte{},
			want:  "",
		},
		{
			name:  "simple data",
			input: []byte("hello"),
			want:  base64.RawURLEncoding.EncodeToString([]byte("hello")),
		},
		{
			name:  "binary data",
			input: []byte{0x01, 0x02, 0x03, 0x04},
			want:  base64.RawURLEncoding.EncodeToString([]byte{0x01, 0x02, 0x03, 0x04}),
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EncodeBase64URL(tt.input)
			if got != tt.want {
				t.Errorf("EncodeBase64URL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDecodeBase64URL(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []byte
		wantErr bool
	}{
		{
			name:    "empty",
			input:   "",
			want:    []byte{},
			wantErr: false,
		},
		{
			name:    "valid encoding",
			input:   EncodeBase64URL([]byte("test")),
			want:    []byte("test"),
			wantErr: false,
		},
		{
			name:    "invalid encoding",
			input:   "!!!invalid!!!",
			want:    nil,
			wantErr: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodeBase64URL(tt.input)
			
			if (err != nil) != tt.wantErr {
				t.Errorf("DecodeBase64URL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			
			if !tt.wantErr {
				if string(got) != string(tt.want) {
					t.Errorf("DecodeBase64URL() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestValidateBase64URL(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "valid empty",
			input:   "",
			wantErr: false,
		},
		{
			name:    "valid encoding",
			input:   EncodeBase64URL([]byte("test data")),
			wantErr: false,
		},
		{
			name:    "invalid characters",
			input:   "not@valid#base64",
			wantErr: true,
		},
		{
			name:    "padding not allowed",
			input:   base64.URLEncoding.EncodeToString([]byte("test")),
			wantErr: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateBase64URL(tt.input)
			
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateBase64URL() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	testData := [][]byte{
		[]byte("hello world"),
		[]byte{0x00, 0x01, 0x02, 0x03},
		[]byte("special chars: !@#$%^&*()"),
		make([]byte, 256), // zeros
	}
	
	for i, data := range testData {
		encoded := EncodeBase64URL(data)
		decoded, err := DecodeBase64URL(encoded)
		
		if err != nil {
			t.Errorf("Test %d: DecodeBase64URL() error = %v", i, err)
			continue
		}
		
		if string(decoded) != string(data) {
			t.Errorf("Test %d: Round trip failed, got %v, want %v", i, decoded, data)
		}
	}
}
