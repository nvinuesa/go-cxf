# go-cxf

A Go library implementing the FIDO Alliance Credential Exchange Format (CXF) v1.0.

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

## Editable field types and constraints

- `string`, `concealed-string`, `email`
- `number` (JSON number)
- `boolean`
- `date` (YYYY-MM-DD, `time.Parse("2006-01-02", s)`)
- `year-month` (YYYY-MM, `time.Parse("2006-01", s)`)
- `wifi-network-security-type` (one of: open, wep, wpa, wpa2, wpa3)
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
  - WiFi: ssid required; security allowed set; password `concealed-string`; hidden `boolean`.
  - Address: country is `country-code`; territory is `subdivision-code`.
  - Identity/Driver/Passport: date fields are `date`; issuingCountry is `country-code`.
  - API key: date fields are `date`; key is `concealed-string`.
  - SSH key: requires at least a private or public key; passphrase `concealed-string`.
  - Item reference: itemId/accountId are base64url ids.
  - Generated password: password non-empty plain string.

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

## Testing & CI

- Local: `go test ./...`
- Formatting: `gofmt -w .`
- CI: GitHub Actions runs gofmt (fail on diff), `go vet ./...`, and `go test ./...` on push/PR (Go 1.21).

## Project structure

```
.
├── cxf.go          # Core types, validators
├── cxf_test.go     # Core validation and round-trip tests
├── cbor.go         # CBOR helpers
├── cbor_test.go    # CBOR round-trip tests
├── utils.go        # Base64/Base32 and ID utilities
├── utils_test.go   # Utility tests
├── examples/       # Example programs
└── README.md       # This file
```

## References

- FIDO Alliance CXF Specification (v1.0 WD 20240522)
- FIDO2 WebAuthn Specification
- COSE (CBOR Object Signing and Encryption)
