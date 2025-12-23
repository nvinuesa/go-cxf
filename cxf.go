// Package cxf implements the FIDO Alliance Credential Exchange Format (CXF) specification.
// This package provides types and functions for creating, parsing, and validating
// CXF credential exchange containers according to the FIDO CXF v1.0 specification.
package cxf

import (
	"encoding/json"
	"errors"
	"time"
)

// Version represents the CXF specification version
const Version = "1.0"

var (
	// ErrInvalidVersion indicates the CXF version is not supported
	ErrInvalidVersion = errors.New("invalid CXF version")
	// ErrInvalidFormat indicates the CXF format is invalid
	ErrInvalidFormat = errors.New("invalid CXF format")
	// ErrMissingCredential indicates no credential is present
	ErrMissingCredential = errors.New("missing credential")
	// ErrInvalidCredentialType indicates an unsupported credential type
	ErrInvalidCredentialType = errors.New("invalid credential type")
)

// Container represents the top-level CXF container structure.
// This is the main structure for exchanging credentials in CXF format.
type Container struct {
	// Version is the CXF specification version (must be "1.0")
	Version string `json:"version"`

	// FormatVersion is the format version for this container
	FormatVersion string `json:"formatVersion,omitempty"`

	// Type indicates the type of container (e.g., "credential", "credential-set")
	Type string `json:"type"`

	// Created is the timestamp when this container was created
	Created time.Time `json:"created"`

	// Credentials contains one or more credentials
	Credentials []Credential `json:"credentials"`

	// Metadata contains additional container metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// Credential represents a single credential within a CXF container.
type Credential struct {
	// ID is a unique identifier for this credential
	ID string `json:"id"`

	// Type specifies the credential type (e.g., "public-key", "passkey")
	Type CredentialType `json:"type"`

	// Created is when the credential was created
	Created time.Time `json:"created"`

	// LastUsed is when the credential was last used
	LastUsed *time.Time `json:"lastUsed,omitempty"`

	// RelyingParty contains information about the relying party
	RelyingParty RelyingParty `json:"relyingParty"`

	// User contains information about the user
	User UserInfo `json:"user"`

	// PublicKey contains the public key information
	PublicKey *PublicKeyCredential `json:"publicKey,omitempty"`

	// PrivateKey contains the private key (if exported)
	PrivateKey *PrivateKeyData `json:"privateKey,omitempty"`

	// Attestation contains attestation data
	Attestation *AttestationData `json:"attestation,omitempty"`

	// Metadata contains additional credential metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// CredentialType represents the type of credential
type CredentialType string

const (
	// CredentialTypePublicKey represents a public key credential
	CredentialTypePublicKey CredentialType = "public-key"

	// CredentialTypePasskey represents a passkey credential
	CredentialTypePasskey CredentialType = "passkey"

	// CredentialTypeFIDO2 represents a FIDO2 credential
	CredentialTypeFIDO2 CredentialType = "fido2"
)

// RelyingParty contains information about the relying party (RP).
type RelyingParty struct {
	// ID is the relying party identifier
	ID string `json:"id"`

	// Name is the human-readable name of the relying party
	Name string `json:"name"`

	// Icon is an optional URL to the relying party icon
	Icon string `json:"icon,omitempty"`
}

// UserInfo contains information about the user associated with a credential.
type UserInfo struct {
	// ID is the user identifier (base64url encoded)
	ID string `json:"id"`

	// Name is the user's account name
	Name string `json:"name"`

	// DisplayName is the user's display name
	DisplayName string `json:"displayName"`

	// Icon is an optional URL to the user's icon
	Icon string `json:"icon,omitempty"`
}

// PublicKeyCredential contains public key credential data.
type PublicKeyCredential struct {
	// CredentialID is the credential identifier (base64url encoded)
	CredentialID string `json:"credentialId"`

	// Algorithm is the COSE algorithm identifier
	Algorithm int `json:"algorithm"`

	// PublicKey is the public key in COSE_Key format (base64url encoded)
	PublicKey string `json:"publicKey"`

	// SignCount is the signature counter value
	SignCount uint32 `json:"signCount"`

	// Transports indicates the supported transports
	Transports []AuthenticatorTransport `json:"transports,omitempty"`

	// AAGUID is the authenticator AAGUID
	AAGUID string `json:"aaguid,omitempty"`
}

// AuthenticatorTransport represents an authenticator transport method
type AuthenticatorTransport string

const (
	// TransportUSB indicates USB transport
	TransportUSB AuthenticatorTransport = "usb"

	// TransportNFC indicates NFC transport
	TransportNFC AuthenticatorTransport = "nfc"

	// TransportBLE indicates Bluetooth Low Energy transport
	TransportBLE AuthenticatorTransport = "ble"

	// TransportInternal indicates platform/internal transport
	TransportInternal AuthenticatorTransport = "internal"

	// TransportHybrid indicates hybrid transport
	TransportHybrid AuthenticatorTransport = "hybrid"
)

// PrivateKeyData contains private key information (for export scenarios).
type PrivateKeyData struct {
	// KeyType specifies the type of private key
	KeyType string `json:"keyType"`

	// PrivateKey is the private key data (base64url encoded)
	PrivateKey string `json:"privateKey"`

	// Encrypted indicates if the private key is encrypted
	Encrypted bool `json:"encrypted,omitempty"`

	// EncryptionMethod specifies the encryption method if encrypted
	EncryptionMethod string `json:"encryptionMethod,omitempty"`
}

// AttestationData contains attestation information.
type AttestationData struct {
	// Format is the attestation statement format
	Format AttestationFormat `json:"format"`

	// Statement is the attestation statement
	Statement map[string]interface{} `json:"statement"`

	// ClientDataJSON is the client data JSON (base64url encoded)
	ClientDataJSON string `json:"clientDataJSON,omitempty"`

	// AuthenticatorData is the authenticator data (base64url encoded)
	AuthenticatorData string `json:"authenticatorData,omitempty"`
}

// AttestationFormat represents the attestation statement format
type AttestationFormat string

const (
	// AttestationFormatPacked represents the packed attestation format
	AttestationFormatPacked AttestationFormat = "packed"

	// AttestationFormatTPM represents the TPM attestation format
	AttestationFormatTPM AttestationFormat = "tpm"

	// AttestationFormatAndroidKey represents the Android Key attestation format
	AttestationFormatAndroidKey AttestationFormat = "android-key"

	// AttestationFormatAndroidSafetyNet represents the Android SafetyNet attestation format
	AttestationFormatAndroidSafetyNet AttestationFormat = "android-safetynet"

	// AttestationFormatFIDOU2F represents the FIDO U2F attestation format
	AttestationFormatFIDOU2F AttestationFormat = "fido-u2f"

	// AttestationFormatNone represents no attestation
	AttestationFormatNone AttestationFormat = "none"

	// AttestationFormatApple represents the Apple attestation format
	AttestationFormatApple AttestationFormat = "apple"
)

// NewContainer creates a new CXF container with the specified type.
func NewContainer(containerType string) *Container {
	return &Container{
		Version:     Version,
		Type:        containerType,
		Created:     time.Now().UTC(),
		Credentials: make([]Credential, 0),
		Metadata:    make(map[string]interface{}),
	}
}

// AddCredential adds a credential to the container.
func (c *Container) AddCredential(cred Credential) {
	c.Credentials = append(c.Credentials, cred)
}

// Validate validates the CXF container structure.
func (c *Container) Validate() error {
	if c.Version != Version {
		return ErrInvalidVersion
	}

	if c.Type == "" {
		return ErrInvalidFormat
	}

	if len(c.Credentials) == 0 {
		return ErrMissingCredential
	}

	for _, cred := range c.Credentials {
		if err := cred.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// Marshal serializes the container to JSON.
func (c *Container) Marshal() ([]byte, error) {
	return json.Marshal(c)
}

// MarshalIndent serializes the container to indented JSON.
func (c *Container) MarshalIndent() ([]byte, error) {
	return json.MarshalIndent(c, "", "  ")
}

// Unmarshal deserializes a JSON byte array into a Container.
func Unmarshal(data []byte) (*Container, error) {
	var container Container
	if err := json.Unmarshal(data, &container); err != nil {
		return nil, err
	}

	return &container, nil
}

// Validate validates the credential structure.
func (c *Credential) Validate() error {
	if c.ID == "" {
		return ErrInvalidFormat
	}

	if c.Type == "" {
		return ErrInvalidCredentialType
	}

	if c.RelyingParty.ID == "" {
		return ErrInvalidFormat
	}

	if c.User.ID == "" {
		return ErrInvalidFormat
	}

	return nil
}

// NewCredential creates a new credential with the specified parameters.
func NewCredential(id string, credType CredentialType, rpID, rpName, userID, userName, userDisplayName string) *Credential {
	return &Credential{
		ID:      id,
		Type:    credType,
		Created: time.Now().UTC(),
		RelyingParty: RelyingParty{
			ID:   rpID,
			Name: rpName,
		},
		User: UserInfo{
			ID:          userID,
			Name:        userName,
			DisplayName: userDisplayName,
		},
		Metadata: make(map[string]interface{}),
	}
}
