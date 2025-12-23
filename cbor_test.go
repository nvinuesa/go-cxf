package cxf

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func TestContainerMarshalCBOR(t *testing.T) {
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
		Algorithm:    -7,
		PublicKey:    "publicKeyData",
		SignCount:    0,
		Transports:   []AuthenticatorTransport{TransportUSB, TransportNFC},
	}

	container.AddCredential(*cred)

	data, err := MarshalContainerCBOR(container)
	if err != nil {
		t.Fatalf("MarshalContainerCBOR() error = %v", err)
	}

	if len(data) == 0 {
		t.Error("Expected non-empty CBOR data")
	}

	// Verify it's valid CBOR by trying to decode it
	var result map[string]interface{}
	if err := cbor.Unmarshal(data, &result); err != nil {
		t.Errorf("Marshaled data is not valid CBOR: %v", err)
	}
}

func TestUnmarshalCBOR(t *testing.T) {
	// Create a container and marshal it
	original := NewContainer("credential")
	cred := NewCredential(
		"cred-1",
		CredentialTypePublicKey,
		"example.com",
		"Example Site",
		"user123",
		"user@example.com",
		"Example User",
	)
	original.AddCredential(*cred)

	data, err := MarshalContainerCBOR(original)
	if err != nil {
		t.Fatalf("MarshalContainerCBOR() error = %v", err)
	}

	// Unmarshal it back
	restored, err := UnmarshalContainerCBOR(data)
	if err != nil {
		t.Fatalf("UnmarshalContainerCBOR() error = %v", err)
	}

	if restored.Version != original.Version {
		t.Errorf("Version mismatch: %s != %s", restored.Version, original.Version)
	}

	if restored.Type != original.Type {
		t.Errorf("Type mismatch: %s != %s", restored.Type, original.Type)
	}

	if len(restored.Credentials) != len(original.Credentials) {
		t.Errorf("Credentials count mismatch: %d != %d", len(restored.Credentials), len(original.Credentials))
	}

	if len(restored.Credentials) > 0 && len(original.Credentials) > 0 {
		if restored.Credentials[0].ID != original.Credentials[0].ID {
			t.Errorf("Credential ID mismatch: %s != %s", restored.Credentials[0].ID, original.Credentials[0].ID)
		}
	}
}

func TestUnmarshalCBORInvalid(t *testing.T) {
	invalidCBOR := []byte{0xff, 0xff, 0xff}

	_, err := UnmarshalContainerCBOR(invalidCBOR)
	if err == nil {
		t.Error("Expected error for invalid CBOR, got nil")
	}
}

func TestCredentialMarshalCBOR(t *testing.T) {
	cred := NewCredential(
		"cred-1",
		CredentialTypePasskey,
		"example.com",
		"Example Site",
		"user123",
		"user@example.com",
		"Example User",
	)

	cred.PublicKey = &PublicKeyCredential{
		CredentialID: "credID",
		Algorithm:    -7,
		PublicKey:    "pubkey",
		SignCount:    10,
	}

	data, err := MarshalCredentialCBOR(cred)
	if err != nil {
		t.Fatalf("MarshalCredentialCBOR() error = %v", err)
	}

	if len(data) == 0 {
		t.Error("Expected non-empty CBOR data")
	}
}

func TestUnmarshalCredentialCBOR(t *testing.T) {
	original := NewCredential(
		"cred-1",
		CredentialTypeFIDO2,
		"example.com",
		"Example Site",
		"user123",
		"user@example.com",
		"Example User",
	)

	data, err := MarshalCredentialCBOR(original)
	if err != nil {
		t.Fatalf("MarshalCredentialCBOR() error = %v", err)
	}

	restored, err := UnmarshalCredentialCBOR(data)
	if err != nil {
		t.Fatalf("UnmarshalCredentialCBOR() error = %v", err)
	}

	if restored.ID != original.ID {
		t.Errorf("ID mismatch: %s != %s", restored.ID, original.ID)
	}

	if restored.Type != original.Type {
		t.Errorf("Type mismatch: %s != %s", restored.Type, original.Type)
	}

	if restored.RelyingParty.ID != original.RelyingParty.ID {
		t.Errorf("RP ID mismatch: %s != %s", restored.RelyingParty.ID, original.RelyingParty.ID)
	}
}

func TestUnmarshalCredentialCBORInvalid(t *testing.T) {
	// Use incomplete CBOR map that expects more data
	invalidCBOR := []byte{0xa1, 0x61, 0x78} // map with 1 element, key "x", but missing value

	_, err := UnmarshalCredentialCBOR(invalidCBOR)
	if err == nil {
		t.Error("Expected error for invalid CBOR, got nil")
	}
}

func TestEncodeCBOR(t *testing.T) {
	tests := []struct {
		name  string
		input interface{}
	}{
		{
			name:  "string",
			input: "test string",
		},
		{
			name:  "number",
			input: 42,
		},
		{
			name:  "map",
			input: map[string]interface{}{"key": "value"},
		},
		{
			name:  "array",
			input: []string{"a", "b", "c"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := EncodeCBOR(tt.input)
			if err != nil {
				t.Errorf("EncodeCBOR() error = %v", err)
			}

			if len(data) == 0 {
				t.Error("Expected non-empty CBOR data")
			}
		})
	}
}

func TestDecodeCBOR(t *testing.T) {
	original := map[string]interface{}{
		"key1": "value1",
		"key2": int64(42),
		"key3": true,
	}

	data, err := EncodeCBOR(original)
	if err != nil {
		t.Fatalf("EncodeCBOR() error = %v", err)
	}

	var decoded map[string]interface{}
	if err := DecodeCBOR(data, &decoded); err != nil {
		t.Fatalf("DecodeCBOR() error = %v", err)
	}

	if decoded["key1"] != original["key1"] {
		t.Errorf("key1 mismatch: %v != %v", decoded["key1"], original["key1"])
	}

	// CBOR may decode integers as uint64 or int64, so use type conversion
	decodedKey2, ok := decoded["key2"].(uint64)
	if !ok {
		decodedKey2Int, ok2 := decoded["key2"].(int64)
		if !ok2 {
			t.Errorf("key2 is not a number: %T", decoded["key2"])
		} else if decodedKey2Int != original["key2"] {
			t.Errorf("key2 mismatch: %v != %v", decodedKey2Int, original["key2"])
		}
	} else if int64(decodedKey2) != original["key2"] {
		t.Errorf("key2 mismatch: %v != %v", decodedKey2, original["key2"])
	}

	if decoded["key3"] != original["key3"] {
		t.Errorf("key3 mismatch: %v != %v", decoded["key3"], original["key3"])
	}
}

func TestCBORRoundTrip(t *testing.T) {
	// Create a full container with all features
	container := NewContainer("credential")

	cred := NewCredential(
		"cred-1",
		CredentialTypePasskey,
		"example.com",
		"Example Site",
		"user123",
		"user@example.com",
		"Example User",
	)

	cred.PublicKey = &PublicKeyCredential{
		CredentialID: "credentialID123",
		Algorithm:    -7,
		PublicKey:    "publicKeyData",
		SignCount:    42,
		Transports:   []AuthenticatorTransport{TransportInternal, TransportUSB},
		AAGUID:       "aaguid123",
	}

	cred.Attestation = &AttestationData{
		Format:            AttestationFormatPacked,
		Statement:         map[string]interface{}{"sig": "signature"},
		ClientDataJSON:    "clientData",
		AuthenticatorData: "authData",
	}

	container.AddCredential(*cred)

	// Marshal to CBOR
	cborData, err := MarshalContainerCBOR(container)
	if err != nil {
		t.Fatalf("MarshalContainerCBOR() error = %v", err)
	}

	// Unmarshal from CBOR
	restored, err := UnmarshalContainerCBOR(cborData)
	if err != nil {
		t.Fatalf("UnmarshalContainerCBOR() error = %v", err)
	}

	// Validate the restored container
	if err := restored.Validate(); err != nil {
		t.Errorf("Restored container validation failed: %v", err)
	}

	// Compare key fields
	if restored.Version != container.Version {
		t.Errorf("Version mismatch: %s != %s", restored.Version, container.Version)
	}

	if len(restored.Credentials) != len(container.Credentials) {
		t.Errorf("Credentials count mismatch: %d != %d", len(restored.Credentials), len(container.Credentials))
	}

	if len(restored.Credentials) > 0 {
		restoredCred := restored.Credentials[0]
		originalCred := container.Credentials[0]

		if restoredCred.ID != originalCred.ID {
			t.Errorf("Credential ID mismatch: %s != %s", restoredCred.ID, originalCred.ID)
		}

		if restoredCred.PublicKey.Algorithm != originalCred.PublicKey.Algorithm {
			t.Errorf("Algorithm mismatch: %d != %d", restoredCred.PublicKey.Algorithm, originalCred.PublicKey.Algorithm)
		}

		if restoredCred.PublicKey.SignCount != originalCred.PublicKey.SignCount {
			t.Errorf("SignCount mismatch: %d != %d", restoredCred.PublicKey.SignCount, originalCred.PublicKey.SignCount)
		}
	}
}

func TestJSONvsCBORSize(t *testing.T) {
	// Create a container with substantial data
	container := NewContainer("credential")

	for i := 0; i < 5; i++ {
		cred := NewCredential(
			"cred-"+string(rune('0'+i)),
			CredentialTypePublicKey,
			"example.com",
			"Example Site",
			"user123",
			"user@example.com",
			"Example User",
		)

		cred.PublicKey = &PublicKeyCredential{
			CredentialID: "credentialID",
			Algorithm:    -7,
			PublicKey:    "publicKeyDataHere",
			SignCount:    uint32(i * 10),
		}

		container.AddCredential(*cred)
	}

	jsonData, err := container.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	cborData, err := MarshalContainerCBOR(container)
	if err != nil {
		t.Fatalf("MarshalContainerCBOR() error = %v", err)
	}

	t.Logf("JSON size: %d bytes", len(jsonData))
	t.Logf("CBOR size: %d bytes", len(cborData))

	// CBOR should typically be smaller than JSON for this kind of data
	// This is informational, not a hard requirement
	if len(cborData) < len(jsonData) {
		t.Logf("CBOR is %.2f%% smaller than JSON",
			100.0*(1.0-float64(len(cborData))/float64(len(jsonData))))
	}
}
