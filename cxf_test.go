package cxf

import (
	"encoding/json"
	"testing"
	"time"
)

func TestNewContainer(t *testing.T) {
	container := NewContainer("credential")
	
	if container.Version != Version {
		t.Errorf("Expected version %s, got %s", Version, container.Version)
	}
	
	if container.Type != "credential" {
		t.Errorf("Expected type 'credential', got %s", container.Type)
	}
	
	if container.Credentials == nil {
		t.Error("Expected credentials slice to be initialized")
	}
	
	if container.Metadata == nil {
		t.Error("Expected metadata map to be initialized")
	}
	
	if container.Created.IsZero() {
		t.Error("Expected created timestamp to be set")
	}
}

func TestContainerAddCredential(t *testing.T) {
	container := NewContainer("credential")
	
	cred := NewCredential(
		"cred-1",
		CredentialTypePublicKey,
		"example.com",
		"Example Site",
		"user123",
		"user@example.com",
		"Example User",
	)
	
	container.AddCredential(*cred)
	
	if len(container.Credentials) != 1 {
		t.Errorf("Expected 1 credential, got %d", len(container.Credentials))
	}
	
	if container.Credentials[0].ID != "cred-1" {
		t.Errorf("Expected credential ID 'cred-1', got %s", container.Credentials[0].ID)
	}
}

func TestContainerValidate(t *testing.T) {
	tests := []struct {
		name      string
		container *Container
		wantErr   error
	}{
		{
			name: "valid container",
			container: func() *Container {
				c := NewContainer("credential")
				cred := NewCredential(
					"cred-1",
					CredentialTypePublicKey,
					"example.com",
					"Example",
					"user123",
					"user@example.com",
					"User",
				)
				c.AddCredential(*cred)
				return c
			}(),
			wantErr: nil,
		},
		{
			name: "invalid version",
			container: &Container{
				Version:     "2.0",
				Type:        "credential",
				Credentials: []Credential{},
			},
			wantErr: ErrInvalidVersion,
		},
		{
			name: "missing type",
			container: &Container{
				Version:     Version,
				Type:        "",
				Credentials: []Credential{},
			},
			wantErr: ErrInvalidFormat,
		},
		{
			name: "missing credentials",
			container: &Container{
				Version:     Version,
				Type:        "credential",
				Credentials: []Credential{},
			},
			wantErr: ErrMissingCredential,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.container.Validate()
			if err != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCredentialValidate(t *testing.T) {
	tests := []struct {
		name       string
		credential *Credential
		wantErr    error
	}{
		{
			name: "valid credential",
			credential: NewCredential(
				"cred-1",
				CredentialTypePublicKey,
				"example.com",
				"Example",
				"user123",
				"user@example.com",
				"User",
			),
			wantErr: nil,
		},
		{
			name: "missing ID",
			credential: &Credential{
				Type: CredentialTypePublicKey,
				RelyingParty: RelyingParty{
					ID:   "example.com",
					Name: "Example",
				},
				User: UserInfo{
					ID:          "user123",
					Name:        "user@example.com",
					DisplayName: "User",
				},
			},
			wantErr: ErrInvalidFormat,
		},
		{
			name: "missing type",
			credential: &Credential{
				ID: "cred-1",
				RelyingParty: RelyingParty{
					ID:   "example.com",
					Name: "Example",
				},
				User: UserInfo{
					ID:          "user123",
					Name:        "user@example.com",
					DisplayName: "User",
				},
			},
			wantErr: ErrInvalidCredentialType,
		},
		{
			name: "missing relying party ID",
			credential: &Credential{
				ID:   "cred-1",
				Type: CredentialTypePublicKey,
				RelyingParty: RelyingParty{
					Name: "Example",
				},
				User: UserInfo{
					ID:          "user123",
					Name:        "user@example.com",
					DisplayName: "User",
				},
			},
			wantErr: ErrInvalidFormat,
		},
		{
			name: "missing user ID",
			credential: &Credential{
				ID:   "cred-1",
				Type: CredentialTypePublicKey,
				RelyingParty: RelyingParty{
					ID:   "example.com",
					Name: "Example",
				},
				User: UserInfo{
					Name:        "user@example.com",
					DisplayName: "User",
				},
			},
			wantErr: ErrInvalidFormat,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.credential.Validate()
			if err != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestContainerMarshal(t *testing.T) {
	container := NewContainer("credential")
	cred := NewCredential(
		"cred-1",
		CredentialTypePublicKey,
		"example.com",
		"Example Site",
		"user123",
		"user@example.com",
		"Example User",
	)
	
	cred.PublicKey = &PublicKeyCredential{
		CredentialID: "abc123",
		Algorithm:    -7, // ES256
		PublicKey:    "publicKeyData",
		SignCount:    0,
		Transports:   []AuthenticatorTransport{TransportUSB, TransportNFC},
	}
	
	container.AddCredential(*cred)
	
	data, err := container.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	
	if len(data) == 0 {
		t.Error("Expected non-empty marshaled data")
	}
	
	// Verify it's valid JSON
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Errorf("Marshaled data is not valid JSON: %v", err)
	}
}

func TestContainerMarshalIndent(t *testing.T) {
	container := NewContainer("credential")
	cred := NewCredential(
		"cred-1",
		CredentialTypePublicKey,
		"example.com",
		"Example",
		"user123",
		"user@example.com",
		"User",
	)
	
	container.AddCredential(*cred)
	
	data, err := container.MarshalIndent()
	if err != nil {
		t.Fatalf("MarshalIndent() error = %v", err)
	}
	
	if len(data) == 0 {
		t.Error("Expected non-empty marshaled data")
	}
	
	// Verify it contains newlines (indented)
	hasNewline := false
	for _, b := range data {
		if b == '\n' {
			hasNewline = true
			break
		}
	}
	
	if !hasNewline {
		t.Error("Expected indented JSON with newlines")
	}
}

func TestUnmarshal(t *testing.T) {
	// Create a valid JSON CXF container
	jsonData := `{
		"version": "1.0",
		"type": "credential",
		"created": "2024-01-01T00:00:00Z",
		"credentials": [
			{
				"id": "cred-1",
				"type": "public-key",
				"created": "2024-01-01T00:00:00Z",
				"relyingParty": {
					"id": "example.com",
					"name": "Example Site"
				},
				"user": {
					"id": "user123",
					"name": "user@example.com",
					"displayName": "Example User"
				}
			}
		]
	}`
	
	container, err := Unmarshal([]byte(jsonData))
	if err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	
	if container.Version != "1.0" {
		t.Errorf("Expected version 1.0, got %s", container.Version)
	}
	
	if container.Type != "credential" {
		t.Errorf("Expected type 'credential', got %s", container.Type)
	}
	
	if len(container.Credentials) != 1 {
		t.Errorf("Expected 1 credential, got %d", len(container.Credentials))
	}
	
	if container.Credentials[0].ID != "cred-1" {
		t.Errorf("Expected credential ID 'cred-1', got %s", container.Credentials[0].ID)
	}
}

func TestUnmarshalInvalid(t *testing.T) {
	invalidJSON := `{"invalid": json}`
	
	_, err := Unmarshal([]byte(invalidJSON))
	if err == nil {
		t.Error("Expected error for invalid JSON, got nil")
	}
}

func TestNewCredential(t *testing.T) {
	cred := NewCredential(
		"cred-1",
		CredentialTypePublicKey,
		"example.com",
		"Example Site",
		"user123",
		"user@example.com",
		"Example User",
	)
	
	if cred.ID != "cred-1" {
		t.Errorf("Expected ID 'cred-1', got %s", cred.ID)
	}
	
	if cred.Type != CredentialTypePublicKey {
		t.Errorf("Expected type %s, got %s", CredentialTypePublicKey, cred.Type)
	}
	
	if cred.RelyingParty.ID != "example.com" {
		t.Errorf("Expected RP ID 'example.com', got %s", cred.RelyingParty.ID)
	}
	
	if cred.User.ID != "user123" {
		t.Errorf("Expected user ID 'user123', got %s", cred.User.ID)
	}
	
	if cred.Created.IsZero() {
		t.Error("Expected created timestamp to be set")
	}
	
	if cred.Metadata == nil {
		t.Error("Expected metadata map to be initialized")
	}
}

func TestCredentialTypes(t *testing.T) {
	types := []CredentialType{
		CredentialTypePublicKey,
		CredentialTypePasskey,
		CredentialTypeFIDO2,
	}
	
	for _, credType := range types {
		cred := NewCredential(
			"test",
			credType,
			"example.com",
			"Example",
			"user123",
			"user@example.com",
			"User",
		)
		
		if cred.Type != credType {
			t.Errorf("Expected type %s, got %s", credType, cred.Type)
		}
	}
}

func TestAuthenticatorTransports(t *testing.T) {
	transports := []AuthenticatorTransport{
		TransportUSB,
		TransportNFC,
		TransportBLE,
		TransportInternal,
		TransportHybrid,
	}
	
	pk := &PublicKeyCredential{
		CredentialID: "test",
		Algorithm:    -7,
		PublicKey:    "key",
		Transports:   transports,
	}
	
	if len(pk.Transports) != len(transports) {
		t.Errorf("Expected %d transports, got %d", len(transports), len(pk.Transports))
	}
}

func TestAttestationFormats(t *testing.T) {
	formats := []AttestationFormat{
		AttestationFormatPacked,
		AttestationFormatTPM,
		AttestationFormatAndroidKey,
		AttestationFormatAndroidSafetyNet,
		AttestationFormatFIDOU2F,
		AttestationFormatNone,
		AttestationFormatApple,
	}
	
	for _, format := range formats {
		attestation := &AttestationData{
			Format:    format,
			Statement: make(map[string]interface{}),
		}
		
		if attestation.Format != format {
			t.Errorf("Expected format %s, got %s", format, attestation.Format)
		}
	}
}

func TestContainerRoundTrip(t *testing.T) {
	// Create a container with full data
	original := NewContainer("credential")
	
	cred := NewCredential(
		"cred-1",
		CredentialTypePasskey,
		"example.com",
		"Example Site",
		"user123",
		"user@example.com",
		"Example User",
	)
	
	lastUsed := time.Now().UTC()
	cred.LastUsed = &lastUsed
	
	cred.PublicKey = &PublicKeyCredential{
		CredentialID: "credentialID123",
		Algorithm:    -7,
		PublicKey:    "publicKeyData",
		SignCount:    42,
		Transports:   []AuthenticatorTransport{TransportInternal},
		AAGUID:       "aaguid123",
	}
	
	cred.Attestation = &AttestationData{
		Format:            AttestationFormatPacked,
		Statement:         map[string]interface{}{"sig": "signature"},
		ClientDataJSON:    "clientData",
		AuthenticatorData: "authData",
	}
	
	original.AddCredential(*cred)
	
	// Marshal
	data, err := original.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	
	// Unmarshal
	restored, err := Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	
	// Validate
	if err := restored.Validate(); err != nil {
		t.Errorf("Restored container validation failed: %v", err)
	}
	
	// Compare key fields
	if restored.Version != original.Version {
		t.Errorf("Version mismatch: %s != %s", restored.Version, original.Version)
	}
	
	if restored.Type != original.Type {
		t.Errorf("Type mismatch: %s != %s", restored.Type, original.Type)
	}
	
	if len(restored.Credentials) != len(original.Credentials) {
		t.Errorf("Credentials count mismatch: %d != %d", len(restored.Credentials), len(original.Credentials))
	}
	
	if len(restored.Credentials) > 0 {
		restoredCred := restored.Credentials[0]
		originalCred := original.Credentials[0]
		
		if restoredCred.ID != originalCred.ID {
			t.Errorf("Credential ID mismatch: %s != %s", restoredCred.ID, originalCred.ID)
		}
		
		if restoredCred.PublicKey.Algorithm != originalCred.PublicKey.Algorithm {
			t.Errorf("Algorithm mismatch: %d != %d", restoredCred.PublicKey.Algorithm, originalCred.PublicKey.Algorithm)
		}
	}
}
