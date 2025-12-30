# go-cxf

Go types for the FIDO Alliance Credential Exchange Format (CXF) v1.0.

[![CI](https://github.com/nvinuesa/go-cxf/actions/workflows/ci.yml/badge.svg)](https://github.com/nvinuesa/go-cxf/actions/workflows/ci.yml)

## Overview

A minimal schema library providing Go structs and constants for the [CXF v1.0 specification](https://fidoalliance.org/specs/cx/cxf-v1.0-rd-20250313.html). The package is primarily type definitions with JSON struct tags and constants; it intentionally does not perform validation.

Inspired by the [Rust reference implementation](https://github.com/bitwarden/credential-exchange/tree/main/credential-exchange-format).

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
	// Build a CXF header using struct literals
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
	header := cxf.Header{
		Version:             cxf.Version{Major: cxf.VersionMajor, Minor: cxf.VersionMinor},
		ExporterRpId:        "exporter.example.com",
		ExporterDisplayName: "Exporter",
		Timestamp:           1710000000,
		Accounts:            []cxf.Account{account},
	}

	// Serialize using standard library
	data, _ := json.MarshalIndent(header, "", "  ")
	fmt.Println(string(data))

	// Deserialize
	var restored cxf.Header
	json.Unmarshal(data, &restored)
}
```

## Core Types

- `Header` (and alias `Container`): Top-level CXF structure with version, exporter info, timestamp, and accounts.
- `Account`: User account with id, username, email, collections, items, and optional extensions.
- `Item`: Credential container with id, title, credentials (as raw JSON), and optional scope/tags/favorite/extensions.
- `Collection`: Organizational grouping of items (with nested sub-collections).
- `LinkedItem`: Reference to an item, optionally in another account.
- `CredentialScope`: URLs and Android app IDs where credentials apply.
- `EditableField`: Typed, user-editable field with `fieldType` and JSON `value`.
- `Extension`: Named extension with arbitrary JSON data.
- Sharing extension model:
  - `SharedExtension`, `SharingAccessor`, `SharingAccessorType`, `SharingAccessorPermission`

## Credential Types

All credential types from the CXF specification are implemented:

| Type | Struct | Description |
|------|--------|-------------|
| `basic-auth` | `BasicAuthCredential` | Username and password |
| `totp` | `TOTPCredential` | Time-based one-time password (RFC 6238) |
| `passkey` | `PasskeyCredential` | WebAuthn private key credential |
| `file` | `FileCredential` | Binary file placeholder with metadata |
| `credit-card` | `CreditCardCredential` | Payment card |
| `note` | `NoteCredential` | Multi-line text note |
| `api-key` | `APIKeyCredential` | API authentication key |
| `address` | `AddressCredential` | Physical address for autofill |
| `generated-password` | `GeneratedPasswordCredential` | Machine-generated password |
| `identity-document` | `IdentityDocumentCredential` | National ID, SSN, TIN |
| `drivers-license` | `DriversLicenseCredential` | Driver's license (ISO 18013-1) |
| `passport` | `PassportCredential` | Passport (ICAO Doc 9303) |
| `person-name` | `PersonNameCredential` | Decomposed name fields |
| `custom-fields` | `CustomFieldsCredential` | User-defined fields |
| `ssh-key` | `SSHKeyCredential` | SSH key pair |
| `wifi` | `WiFiCredential` | Wi-Fi network credentials |
| `item-reference` | `ItemReferenceCredential` | Cross-link to another item |

## Field Types

Constants for `EditableField.FieldType`:

- `FieldTypeString` - Plain text
- `FieldTypeConcealedString` - Secret text (passwords, etc.)
- `FieldTypeEmail` - Email address
- `FieldTypeNumber` - Numeric value
- `FieldTypeBoolean` - Boolean ("true"/"false")
- `FieldTypeDate` - Date (YYYY-MM-DD)
- `FieldTypeYearMonth` - Year and month (YYYY-MM)
- `FieldTypeWifiNetworkSecurity` - Wi-Fi security type
- `FieldTypeCountryCode` - ISO 3166-1 alpha-2
- `FieldTypeSubdivisionCode` - ISO 3166-2

## Design Philosophy

This library intentionally focuses on schema representation:

- **Primarily types and constants** - The core is Go structs with JSON tags and string constants.
- **No validation** - Validation is application-specific. Use your own validation logic.
- **JSON-first** - Use `encoding/json` (`json.Marshal`/`json.Unmarshal`) directly.
- **Raw JSON for forward compatibility** - Some fields are `json.RawMessage` (e.g., `Item.Credentials`, `EditableField.Value`, `Extension.Data`), so consumers must treat them as untrusted input and validate before use.

## References

- [FIDO Alliance CXF Specification (v1.0 RD 20250313)](https://fidoalliance.org/specs/cx/cxf-v1.0-rd-20250313.html)
- [Rust Reference Implementation](https://github.com/nicholastmosher/credential-exchange/tree/main/credential-exchange-format)

## License

See [LICENSE](LICENSE) file.
