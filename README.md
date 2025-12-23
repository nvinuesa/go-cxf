# go-cxf

A Go library implementing the FIDO Alliance Credential Exchange Format (CXF) v1.0 (draft https://fidoalliance.org/specs/cx/cxf-v1.0-rd-20250313.html).

[![CI](https://github.com/nvinuesa/go-cxf/actions/workflows/ci.yml/badge.svg)](https://github.com/nvinuesa/go-cxf/actions/workflows/ci.yml)

## Overview

- JSON and CBOR serialization for CXF headers.
- Rich credential type coverage with strong validation.
- Base64URL/Base32 utilities and identifier helpers.
- Zero external dependencies beyond CBOR (fxamacker/cbor).

## Installation

```bash
go get github.com/nvinuesa/go-cxf
```

## Quick Start

```go
package main

import (
	"encoding/json"
	"fmt"

	"github.com/nvinuesa/go-cxf"
)

func main() {
	// Build a minimal header (alias: Container).
	cred := json.RawMessage(`{"type":"totp","secret":"JBSWY3DPEHPK3PXP","algorithm":"sha1","period":30,"digits":6}`)
	item := cxf.Item{
		ID:          "aXRlbS0x", // base64url("item-1")
		Title:       "My TOTP",
		Credentials: []json.RawMessage{cred},
	}
	account := cxf.Account{
		ID:       "YWNjb3VudC0x", // base64url("account-1")
		Username: "user",
		Email:    "user@example.com",
		Items:    []cxf.Item{item},
	}
	header := &cxf.Header{
		Version: cxf.Version{Major: cxf.VersionMajor, Minor: cxf.VersionMinor},
		ExporterRpId:        "exporter.example.com",
		ExporterDisplayName: "Exporter",
		Timestamp:           1710000000,
		Accounts:            []cxf.Account{account},
	}

	// Validate
	if err := header.Validate(); err != nil {
		panic(err)
	}

	// JSON round trip
	data, _ := header.MarshalIndent()
	fmt.Println(string(data))
}
```

## Core types

- `Header` (alias `Container`): top-level CXF structure with version, exporter info, timestamp, accounts.
- `Account`: id, username, email, collections, items.
- `Item`: id, title, credentials, optional scope/tags/favorite.
- `CredentialScope`: urls and Android app IDs.
- `EditableField`: typed, user-editable field with `fieldType` and JSON `value`.
- `Extension`: name + arbitrary data map.

## Credential types

Implemented and validated:

- `basic-auth`
- `totp`
- `passkey`
- `file`
- `credit-card`
- `note`
- `api-key`
- `address`
- `generated-password`
- `identity-document`
- `drivers-license`
- `passport`
- `person-name`
- `custom-fields`
- `ssh-key`
- `wifi`
- `item-reference`

Unknown credential types are passed through without error, per the CXF specification.

## Editable field types and constraints

- `string`, `concealed-string`, `email`
- `number` (JSON number)
- `boolean`
- `date` (YYYY-MM-DD, `time.Parse("2006-01-02", s)`)
- `year-month` (YYYY-MM, `time.Parse("2006-01", s)`)
- `wifi-network-security-type` (one of: unsecured, wep, wpa-personal, wpa2-personal, wpa3-personal)
- `country-code` (exactly 2 uppercase ASCII letters)
- `subdivision-code` (must contain one dash, e.g., US-CA)

All editable fields must include `fieldType` and non-empty `value`; optional `id` must be valid base64url (<=64 decoded bytes).

## Validation highlights

- Header: version must match `VersionMajor/VersionMinor`; exporter fields and timestamp required; at least one account.
- Account: id/username/email required; id must be base64url (<=64 bytes); at least one item.
- Item: id/title required; id must be base64url (<=64 bytes); at least one credential.
- Each credential type enforces required members, field types, and encodings:
  - TOTP: algorithm in {sha1, sha256, sha512}; digits in {6,7,8}; secret base32.
  - Passkey: ids/handles/keys base64url; HMAC secrets decode to 32 bytes; largeBlob data base64url.
  - File: id base64url; integrityHash base64url; name non-empty; decryptedSize > 0.
  - Credit card: expiry/validFrom are `year-month`; number/CVV/PIN are `concealed-string`.
  - WiFi: networkSecurityType must be valid; passphrase `concealed-string`; hidden `boolean`.
  - Address: country is `country-code`; territory is `subdivision-code`.
  - Identity document: includes birthDate, birthPlace, sex, identificationNumber, nationality fields.
  - Driver's license: includes birthDate, territory (subdivision-code), licenseNumber, licenseClass.
  - Passport: includes passportNumber, passportType, birthDate, birthPlace, sex, nationality.
  - Person name: uses title, given, givenInformal, given2, surnamePrefix, surname, surname2, credentials, generation.
  - API key: date fields are `date`; key is `concealed-string`.
  - SSH key: requires `keyType` and `privateKey` (base64url PKCS#8 DER); optional keyComment, creationDate, expiryDate.
  - Item reference: uses `reference` containing a LinkedItem with item/account IDs.
  - Generated password: password non-empty plain string.
  - Custom fields: supports optional id, label, and extensions.

Use `ValidateCredential` or `ValidateCredentials` for individual checks; `Header.Validate()` walks the full tree.

## Serialization

- JSON: `Header.Marshal()` / `Header.MarshalIndent()` and standard `json.Unmarshal`.
- CBOR: `MarshalHeaderCBOR` / `UnmarshalHeaderCBOR` plus generic `EncodeCBOR` / `DecodeCBOR`.
- Integrity: `ComputeIntegrityHash` returns base64url-encoded SHA-256; `ValidateIntegrityHash` compares hashes.

## Utilities

- `EncodeBase64URL`, `DecodeBase64URL`, `ValidateBase64URL`
- `EncodeBase32`, `DecodeBase32`, `ValidateBase32`
- `GenerateIdentifier` (alias: `GenerateCredentialID`, `GenerateUserID`) produce base64url ids of given length (<=64 decoded bytes).
- `ValidateIdentifier` ensures base64url and length <= 64 decoded bytes.

## Development

### Using Make

```bash
# Run all checks (format, vet, test)
make

# Run tests
make test

# Run tests with coverage
make test-coverage

# Format code
make fmt

# Run linting (go vet)
make vet

# Clean build artifacts
make clean

# Show all available targets
make help
```

### Manual commands

```bash
# Run tests
go test ./...

# Format code
gofmt -w .

# Run vet
go vet ./...
```

### CI

GitHub Actions runs format check, `go vet`, and tests on push/PR to main.

## Project structure

```
.
├── cxf.go          # Core types, validators
├── cxf_test.go     # Core validation and round-trip tests
├── cbor.go         # CBOR helpers
├── cbor_test.go    # CBOR round-trip tests
├── utils.go        # Base64/Base32 and ID utilities
├── utils_test.go   # Utility tests
├── Makefile        # Build automation
├── examples/       # Example programs
└── README.md       # This file
```

## References

- [FIDO Alliance CXF Specification (v1.0 RD 20250313)](https://fidoalliance.org/specs/cx/cxf-v1.0-rd-20250313.html)
- [Bitwarden Credential Exchange Reference Implementation](https://github.com/bitwarden/credential-exchange)
- FIDO2 WebAuthn Specification
- COSE (CBOR Object Signing and Encryption)

## License

See [LICENSE](LICENSE) file.
