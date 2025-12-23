# go-cxf

A Go library implementing the FIDO Alliance Credential Exchange Format (CXF) v1.0 specification.

## Overview

go-cxf provides a complete implementation of the CXF specification for exchanging FIDO credentials in a standardized format. The library supports both JSON and CBOR serialization formats, making it suitable for various use cases including credential backup, migration, and synchronization.

## Features

- ✅ Full CXF v1.0 specification compliance
- ✅ Support for multiple credential types (public-key, passkey, FIDO2)
- ✅ JSON and CBOR serialization/deserialization
- ✅ Comprehensive validation
- ✅ Base64URL encoding/decoding utilities
- ✅ Credential and user ID generation
- ✅ Extensive test coverage
- ✅ Type-safe API
- ✅ Zero external dependencies (except CBOR library)

## Installation

```bash
go get github.com/nvinuesa/go-cxf
```

## Quick Start

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/nvinuesa/go-cxf"
)

func main() {
    // Create a new CXF container
    container := cxf.NewContainer("credential")
    
    // Generate IDs
    credID, _ := cxf.GenerateCredentialID(32)
    userID, _ := cxf.GenerateUserID(32)
    
    // Create a credential
    cred := cxf.NewCredential(
        credID,
        cxf.CredentialTypePasskey,
        "example.com",
        "Example Site",
        userID,
        "user@example.com",
        "Example User",
    )
    
    // Add public key information
    cred.PublicKey = &cxf.PublicKeyCredential{
        CredentialID: credID,
        Algorithm:    -7, // ES256
        PublicKey:    cxf.EncodeBase64URL([]byte("public-key-data")),
        SignCount:    0,
        Transports:   []cxf.AuthenticatorTransport{cxf.TransportInternal},
    }
    
    // Add to container
    container.AddCredential(*cred)
    
    // Serialize to JSON
    jsonData, err := container.MarshalIndent()
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Println(string(jsonData))
}
```

## Core Types

### Container

The `Container` is the top-level structure for CXF credential exchange:

```go
type Container struct {
    Version       string                 // CXF specification version
    FormatVersion string                 // Format version
    Type          string                 // Container type
    Created       time.Time              // Creation timestamp
    Credentials   []Credential           // List of credentials
    Metadata      map[string]interface{} // Additional metadata
}
```

### Credential

The `Credential` represents a single credential:

```go
type Credential struct {
    ID           string                 // Unique identifier
    Type         CredentialType         // Credential type
    Created      time.Time              // Creation timestamp
    LastUsed     *time.Time             // Last usage timestamp
    RelyingParty RelyingParty           // Relying party information
    User         UserInfo               // User information
    PublicKey    *PublicKeyCredential   // Public key data
    PrivateKey   *PrivateKeyData        // Private key (if exported)
    Attestation  *AttestationData       // Attestation information
    Metadata     map[string]interface{} // Additional metadata
}
```

## Credential Types

The library supports the following credential types:

- `CredentialTypePublicKey` - Public key credentials
- `CredentialTypePasskey` - Passkey credentials
- `CredentialTypeFIDO2` - FIDO2 credentials

## Serialization Formats

### JSON

```go
// Marshal to JSON
jsonData, err := container.Marshal()

// Marshal with indentation
jsonData, err := container.MarshalIndent()

// Unmarshal from JSON
container, err := cxf.Unmarshal(jsonData)
```

### CBOR

```go
// Marshal to CBOR
cborData, err := cxf.MarshalContainerCBOR(container)

// Unmarshal from CBOR
container, err := cxf.UnmarshalContainerCBOR(cborData)
```

CBOR encoding typically results in 20-30% smaller payloads compared to JSON.

## Validation

The library provides comprehensive validation:

```go
// Validate container
if err := container.Validate(); err != nil {
    log.Printf("Validation failed: %v", err)
}

// Validate individual credential
if err := credential.Validate(); err != nil {
    log.Printf("Credential validation failed: %v", err)
}
```

## Utility Functions

### ID Generation

```go
// Generate credential ID (32 bytes)
credID, err := cxf.GenerateCredentialID(32)

// Generate user ID (32 bytes)
userID, err := cxf.GenerateUserID(32)
```

### Base64URL Encoding

```go
// Encode to base64url
encoded := cxf.EncodeBase64URL([]byte("data"))

// Decode from base64url
decoded, err := cxf.DecodeBase64URL(encoded)

// Validate base64url string
err := cxf.ValidateBase64URL(encoded)
```

## Attestation Formats

The library supports all standard FIDO attestation formats:

- `AttestationFormatPacked` - Packed attestation
- `AttestationFormatTPM` - TPM attestation
- `AttestationFormatAndroidKey` - Android Key attestation
- `AttestationFormatAndroidSafetyNet` - Android SafetyNet attestation
- `AttestationFormatFIDOU2F` - FIDO U2F attestation
- `AttestationFormatApple` - Apple attestation
- `AttestationFormatNone` - No attestation

## Authenticator Transports

Supported authenticator transports:

- `TransportUSB` - USB
- `TransportNFC` - NFC
- `TransportBLE` - Bluetooth Low Energy
- `TransportInternal` - Platform/internal authenticator
- `TransportHybrid` - Hybrid transport

## Examples

See the [examples/basic](examples/basic/main.go) directory for complete examples including:

- Basic container creation
- Complete credentials with attestation
- Multiple credentials handling
- JSON and CBOR serialization comparison

To run the examples:

```bash
cd examples/basic
go run main.go
```

## Testing

Run the test suite:

```bash
go test -v ./...
```

Run tests with coverage:

```bash
go test -v -cover ./...
```

## Project Structure

```
.
├── cxf.go          # Core types and functions
├── cxf_test.go     # Core tests
├── cbor.go         # CBOR serialization support
├── cbor_test.go    # CBOR tests
├── utils.go        # Utility functions
├── utils_test.go   # Utility tests
├── examples/       # Example programs
└── README.md       # This file
```

## COSE Algorithm Identifiers

Common COSE algorithm identifiers used in the library:

- `-7` - ES256 (ECDSA with SHA-256)
- `-35` - ES384 (ECDSA with SHA-384)
- `-36` - ES512 (ECDSA with SHA-512)
- `-8` - EdDSA
- `-257` - RS256 (RSASSA-PKCS1-v1_5 with SHA-256)

## Contributing

Contributions are welcome! Please ensure:

1. All tests pass: `go test ./...`
2. Code is formatted: `go fmt ./...`
3. Code is linted: `go vet ./...`
4. New features include tests
5. Commits follow conventional commit format

## Conventional Commits

This project uses conventional commits for clear and semantic commit messages:

- `feat:` - New features
- `fix:` - Bug fixes
- `docs:` - Documentation changes
- `test:` - Test additions or modifications
- `refactor:` - Code refactoring
- `chore:` - Maintenance tasks

## License

This project is licensed under the GNU Affero General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## References

- [FIDO Alliance CXF Specification](https://fidoalliance.org/specs/cx/cxf-v1.0-wd-20240522.html)
- [FIDO2 WebAuthn Specification](https://www.w3.org/TR/webauthn/)
- [COSE (CBOR Object Signing and Encryption)](https://tools.ietf.org/html/rfc8152)

## Support

For issues, questions, or contributions, please open an issue on the GitHub repository.
