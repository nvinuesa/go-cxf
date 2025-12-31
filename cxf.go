// Package cxf provides Go types for the Credential Exchange Format (CXF),
// an open standard for securely exchanging credentials between password
// managers and other applications. It defines structures for accounts,
// collections, items, and various credential types including passwords,
// passkeys, TOTP, SSH keys, credit cards, and more.
package cxf

import (
	"encoding/json"
)

const (
	// VersionMajor represents the CXF major version.
	VersionMajor uint8 = 1
	// VersionMinor represents the CXF minor version.
	VersionMinor uint8 = 0
)

// Version encodes the CXF format version information.
type Version struct {
	// Breaking change version.
	Major uint8 `json:"major"`
	// Additive functionality version.
	Minor uint8 `json:"minor"`
}

// Header is the top-level CXF structure containing all exported data.
type Header struct {
	// Format version.
	Version Version `json:"version"`
	// FIDO RP ID of the exporting application.
	ExporterRpId string `json:"exporterRpId"`
	// Human-readable display name for the exporting application.
	ExporterDisplayName string `json:"exporterDisplayName"`
	// UNIX timestamp (seconds since epoch) when the export was created.
	Timestamp uint64 `json:"timestamp"`
	// List of accounts being exported.
	Accounts []Account `json:"accounts"`
}

// Container is kept as an alias for backwards compatibility with previous code paths.
type Container = Header

// Account represents a credential owner's account in the exporting application.
type Account struct {
	// Unique identifier for this account (base64url-encoded, max 64 bytes decoded).
	ID string `json:"id"`
	// User-defined pseudonym for the account.
	Username string `json:"username"`
	// Email address used for account registration.
	Email string `json:"email"`
	// User's full name.
	FullName string `json:"fullName,omitempty"`
	// Collections owned by this account.
	Collections []Collection `json:"collections"`
	// Items owned by this account.
	Items []Item `json:"items"`
	// Account-level extensions.
	Extensions []Extension `json:"extensions,omitempty"`
}

// Collection groups items together for organizational purposes.
type Collection struct {
	// Unique identifier for this collection (base64url-encoded, max 64 bytes decoded).
	ID string `json:"id"`
	// UNIX timestamp when the collection was created.
	CreationAt *uint64 `json:"creationAt,omitempty"`
	// UNIX timestamp when the collection was last modified.
	ModifiedAt *uint64 `json:"modifiedAt,omitempty"`
	// Display name for the collection.
	Title string `json:"title"`
	// Description of the collection.
	Subtitle string `json:"subtitle,omitempty"`
	// References to items in this collection.
	Items []LinkedItem `json:"items"`
	// Nested sub-collections.
	SubCollections []Collection `json:"subCollections,omitempty"`
	// Collection-level extensions.
	Extensions []Extension `json:"extensions,omitempty"`
}

// LinkedItem points to an item, optionally in a different account.
type LinkedItem struct {
	// ID of the referenced item.
	Item string `json:"item"`
	// ID of the account owning the item, if different from the current account.
	Account string `json:"account,omitempty"`
}

// Item contains metadata and one or more credentials.
type Item struct {
	// Unique identifier for this item (base64url-encoded, max 64 bytes decoded).
	ID string `json:"id"`
	// UNIX timestamp when the item was created.
	CreationAt *uint64 `json:"creationAt,omitempty"`
	// UNIX timestamp when the item was last modified.
	ModifiedAt *uint64 `json:"modifiedAt,omitempty"`
	// User-defined name for the item.
	Title string `json:"title"`
	// Description of the item.
	Subtitle string `json:"subtitle,omitempty"`
	// Whether the item is marked as a favorite.
	Favorite *bool `json:"favorite,omitempty"`
	// Defines where the credentials should be presented.
	Scope *CredentialScope `json:"scope,omitempty"`
	// List of credentials associated with this item.
	Credentials []json.RawMessage `json:"credentials"`
	// User-defined tags for categorization.
	Tags []string `json:"tags,omitempty"`
	// Item-level extensions.
	Extensions []Extension `json:"extensions,omitempty"`
}

// CredentialScope defines where credentials should be auto-filled.
type CredentialScope struct {
	// List of URIs (RFC 3986) where the credentials apply.
	Urls []string `json:"urls"`
	// List of Android applications where the credentials apply.
	AndroidApps []AndroidAppIdCredential `json:"androidApps"`
}

// AndroidAppIdCredential identifies an Android application for credential scoping.
type AndroidAppIdCredential struct {
	// Android application package identifier (e.g., "com.example.myapp").
	BundleId string `json:"bundleId"`
	// Signing certificate fingerprint for verification.
	Certificate *AndroidAppCertificateFingerprint `json:"certificate,omitempty"`
	// Human-readable application name.
	Name string `json:"name,omitempty"`
}

// AndroidAppCertificateFingerprint stores a hash of an Android app's signing certificate.
type AndroidAppCertificateFingerprint struct {
	// Base64url-encoded hash of the signing certificate.
	Fingerprint string `json:"fingerprint"`
	// Hash algorithm used (e.g., "sha256", "sha1").
	HashAlg string `json:"hashAlg"`
}

// AndroidAppHashAlgorithm constants for certificate fingerprint hash algorithms.
const (
	AndroidAppHashAlgorithmSha256 = "sha256"
	AndroidAppHashAlgorithmSha1   = "sha1"
)

// EditableField represents a user-editable field with a typed value.
type EditableField struct {
	// Unique identifier for this field within an item (base64url-encoded, max 64 bytes decoded).
	ID string `json:"id,omitempty"`
	// Type of the field value (see FieldType constants).
	FieldType string `json:"fieldType"`
	// The actual field value (string representation).
	Value json.RawMessage `json:"value"`
	// User-facing description of the field.
	Label string `json:"label,omitempty"`
	// Field-level extensions.
	Extensions []Extension `json:"extensions,omitempty"`
}

// FieldType constants define the type of value in an EditableField.
const (
	// Unconcealed, unformatted UTF-8 string.
	FieldTypeString = "string"
	// Secret text that should not be displayed by default.
	FieldTypeConcealedString = "concealed-string"
	// RFC 5322 compliant email address.
	FieldTypeEmail = "email"
	// Stringified numeric value.
	FieldTypeNumber = "number"
	// Boolean value serialized as "true" or "false" string.
	FieldTypeBoolean = "boolean"
	// Date in RFC 3339 full-date format (YYYY-MM-DD).
	FieldTypeDate = "date"
	// Year and month in YYYY-MM format (RFC 3339 Appendix A).
	FieldTypeYearMonth = "year-month"
	// Wi-Fi network security type (see WifiNetworkSecurityType constants).
	FieldTypeWifiNetworkSecurity = "wifi-network-security-type"
	// ISO 3166-1 alpha-2 country code.
	FieldTypeCountryCode = "country-code"
	// ISO 3166-2 subdivision code.
	FieldTypeSubdivisionCode = "subdivision-code"
)

// WifiNetworkSecurityType constants for Wi-Fi network security modes.
const (
	// No authentication required.
	WifiSecurityUnsecured = "unsecured"
	// WPA-Personal security.
	WifiSecurityWPAPersonal = "wpa-personal"
	// WPA2-Personal security.
	WifiSecurityWPA2Personal = "wpa2-personal"
	// WPA3-Personal security.
	WifiSecurityWPA3Personal = "wpa3-personal"
	// WEP security (legacy).
	WifiSecurityWEP = "wep"
)

// CredentialType constants define the type discriminator for credential structs.
const (
	// Address autofill credential.
	CredentialTypeAddress = "address"
	// API key authentication credential.
	CredentialTypeAPIKey = "api-key"
	// Username and password credential.
	CredentialTypeBasicAuth = "basic-auth"
	// Payment card credential.
	CredentialTypeCreditCard = "credit-card"
	// User-defined custom fields credential.
	CredentialTypeCustomFields = "custom-fields"
	// Driver's license credential (ISO 18013-1).
	CredentialTypeDriversLicense = "drivers-license"
	// Binary file placeholder credential.
	CredentialTypeFile = "file"
	// Machine-generated password credential.
	CredentialTypeGeneratedPassword = "generated-password"
	// National ID, SSN, TIN, or insurance card credential.
	CredentialTypeIdentityDocument = "identity-document"
	// Reference to another item credential.
	CredentialTypeItemReference = "item-reference"
	// Multi-line text note credential.
	CredentialTypeNote = "note"
	// WebAuthn passkey credential.
	CredentialTypePasskey = "passkey"
	// Passport credential (ICAO Doc 9303).
	CredentialTypePassport = "passport"
	// Decomposed person name credential (Unicode LDML Part 8).
	CredentialTypePersonName = "person-name"
	// SSH key pair credential.
	CredentialTypeSSHKey = "ssh-key"
	// Time-based one-time password credential (RFC 4226/6238).
	CredentialTypeTOTP = "totp"
	// Wi-Fi network credential.
	CredentialTypeWiFi = "wifi"
)

// APIKeyCredential represents an API key for authentication.
type APIKeyCredential struct {
	// Credential type discriminator.
	Type string `json:"type"`
	// The API key value (concealed-string).
	Key *EditableField `json:"key,omitempty"`
	// Username associated with the API key.
	Username *EditableField `json:"username,omitempty"`
	// Type of API key (e.g., "Bearer", "JWT").
	KeyType *EditableField `json:"keyType,omitempty"`
	// URL where the API key is used.
	URL *EditableField `json:"url,omitempty"`
	// Date from which the key is valid.
	ValidFrom *EditableField `json:"validFrom,omitempty"`
	// Date when the key expires.
	ExpiryDate *EditableField `json:"expiryDate,omitempty"`
}

// AddressCredential represents a physical address for autofill.
type AddressCredential struct {
	// Credential type discriminator.
	Type string `json:"type"`
	// Street address (may contain multiple lines).
	StreetAddress *EditableField `json:"streetAddress,omitempty"`
	// Postal or ZIP code.
	PostalCode *EditableField `json:"postalCode,omitempty"`
	// City name.
	City *EditableField `json:"city,omitempty"`
	// State/province/region (ISO 3166-2 subdivision code).
	Territory *EditableField `json:"territory,omitempty"`
	// Country (ISO 3166-1 alpha-2 country code).
	Country *EditableField `json:"country,omitempty"`
	// Telephone number.
	Tel *EditableField `json:"tel,omitempty"`
}

// GeneratedPasswordCredential represents a machine-generated password.
type GeneratedPasswordCredential struct {
	// Credential type discriminator.
	Type string `json:"type"`
	// The generated password value (displayed as concealed).
	Password string `json:"password"`
}

// PersonNameCredential represents decomposed name fields (Unicode LDML Part 8).
type PersonNameCredential struct {
	// Credential type discriminator.
	Type string `json:"type"`
	// Title or honorific (e.g., "Ms.", "Mr.", "Dr.").
	Title *EditableField `json:"title,omitempty"`
	// Given name (first name).
	Given *EditableField `json:"given,omitempty"`
	// Informal/preferred name or nickname.
	GivenInformal *EditableField `json:"givenInformal,omitempty"`
	// Additional given names (middle names).
	Given2 *EditableField `json:"given2,omitempty"`
	// Surname prefix (e.g., "van", "de").
	SurnamePrefix *EditableField `json:"surnamePrefix,omitempty"`
	// Surname (family name).
	Surname *EditableField `json:"surname,omitempty"`
	// Secondary surname.
	Surname2 *EditableField `json:"surname2,omitempty"`
	// Professional credentials (e.g., "PhD", "MBA").
	Credentials *EditableField `json:"credentials,omitempty"`
	// Generational suffix (e.g., "Jr.", "III").
	Generation *EditableField `json:"generation,omitempty"`
}

// IdentityDocumentCredential represents national IDs, SSN, TIN, or insurance cards.
type IdentityDocumentCredential struct {
	// Credential type discriminator.
	Type string `json:"type"`
	// Country that issued the document (ISO 3166-1 alpha-2).
	IssuingCountry *EditableField `json:"issuingCountry,omitempty"`
	// Document number.
	DocumentNumber *EditableField `json:"documentNumber,omitempty"`
	// Identification number on the document.
	IdentificationNumber *EditableField `json:"identificationNumber,omitempty"`
	// Holder's nationality.
	Nationality *EditableField `json:"nationality,omitempty"`
	// Holder's full name.
	FullName *EditableField `json:"fullName,omitempty"`
	// Holder's date of birth.
	BirthDate *EditableField `json:"birthDate,omitempty"`
	// Holder's place of birth.
	BirthPlace *EditableField `json:"birthPlace,omitempty"`
	// Holder's sex.
	Sex *EditableField `json:"sex,omitempty"`
	// Date when the document was issued.
	IssueDate *EditableField `json:"issueDate,omitempty"`
	// Date when the document expires.
	ExpiryDate *EditableField `json:"expiryDate,omitempty"`
	// Authority that issued the document.
	IssuingAuthority *EditableField `json:"issuingAuthority,omitempty"`
}

// DriversLicenseCredential represents a driver's license (ISO 18013-1).
type DriversLicenseCredential struct {
	// Credential type discriminator.
	Type string `json:"type"`
	// Holder's full name.
	FullName *EditableField `json:"fullName,omitempty"`
	// Holder's date of birth.
	BirthDate *EditableField `json:"birthDate,omitempty"`
	// Date when the license was issued.
	IssueDate *EditableField `json:"issueDate,omitempty"`
	// Date when the license expires.
	ExpiryDate *EditableField `json:"expiryDate,omitempty"`
	// Authority that issued the license.
	IssuingAuthority *EditableField `json:"issuingAuthority,omitempty"`
	// State/province/region (ISO 3166-2 subdivision code).
	Territory *EditableField `json:"territory,omitempty"`
	// Country (ISO 3166-1 alpha-2 country code).
	Country *EditableField `json:"country,omitempty"`
	// License number.
	LicenseNumber *EditableField `json:"licenseNumber,omitempty"`
	// License class or category.
	LicenseClass *EditableField `json:"licenseClass,omitempty"`
}

// PassportCredential represents a passport (ICAO Doc 9303 Part 4).
type PassportCredential struct {
	// Credential type discriminator.
	Type string `json:"type"`
	// Country that issued the passport (ISO 3166-1 alpha-2).
	IssuingCountry *EditableField `json:"issuingCountry,omitempty"`
	// Passport type (per ICAO Doc 9303).
	PassportType *EditableField `json:"passportType,omitempty"`
	// Passport number.
	PassportNumber *EditableField `json:"passportNumber,omitempty"`
	// National identification number.
	NationalIdentificationNumber *EditableField `json:"nationalIdentificationNumber,omitempty"`
	// Holder's nationality.
	Nationality *EditableField `json:"nationality,omitempty"`
	// Holder's full name.
	FullName *EditableField `json:"fullName,omitempty"`
	// Holder's date of birth.
	BirthDate *EditableField `json:"birthDate,omitempty"`
	// Holder's place of birth.
	BirthPlace *EditableField `json:"birthPlace,omitempty"`
	// Holder's sex.
	Sex *EditableField `json:"sex,omitempty"`
	// Date when the passport was issued.
	IssueDate *EditableField `json:"issueDate,omitempty"`
	// Date when the passport expires.
	ExpiryDate *EditableField `json:"expiryDate,omitempty"`
	// Authority that issued the passport.
	IssuingAuthority *EditableField `json:"issuingAuthority,omitempty"`
}

// CustomFieldsCredential represents user-defined custom field groupings.
type CustomFieldsCredential struct {
	// Credential type discriminator.
	Type string `json:"type"`
	// Unique identifier (base64url-encoded, max 64 bytes decoded).
	ID string `json:"id,omitempty"`
	// Human-readable section title.
	Label string `json:"label,omitempty"`
	// Heterogeneous collection of fields.
	Fields []EditableField `json:"fields"`
	// Custom extensions.
	Extensions []Extension `json:"extensions,omitempty"`
}

// SSHKeyCredential represents an SSH key pair.
type SSHKeyCredential struct {
	// Credential type discriminator.
	Type string `json:"type"`
	// SSH algorithm identifier (e.g., "ssh-rsa", "ssh-ed25519", "ecdsa-sha2-nistp256").
	KeyType string `json:"keyType"`
	// PKCS#8 ASN.1 DER formatted private key, base64url-encoded.
	PrivateKey string `json:"privateKey"`
	// User-defined key identifier/comment.
	KeyComment string `json:"keyComment,omitempty"`
	// Date when the key was created.
	CreationDate *EditableField `json:"creationDate,omitempty"`
	// Date when the key expires.
	ExpiryDate *EditableField `json:"expiryDate,omitempty"`
	// Source/tool used to generate the key.
	KeyGenerationSource *EditableField `json:"keyGenerationSource,omitempty"`
}

// WiFiCredential represents Wi-Fi network credentials.
type WiFiCredential struct {
	// Credential type discriminator.
	Type string `json:"type"`
	// Network SSID.
	SSID *EditableField `json:"ssid,omitempty"`
	// Network security type (wifi-network-security-type).
	NetworkSecurityType *EditableField `json:"networkSecurityType,omitempty"`
	// Network passphrase (concealed-string).
	Passphrase *EditableField `json:"passphrase,omitempty"`
	// Whether the network is hidden.
	Hidden *EditableField `json:"hidden,omitempty"`
}

// ItemReferenceCredential represents a cross-link to another item.
type ItemReferenceCredential struct {
	// Credential type discriminator.
	Type string `json:"type"`
	// Reference to another item.
	Reference LinkedItem `json:"reference"`
}

// BasicAuthCredential represents a username and password credential.
type BasicAuthCredential struct {
	// Credential type discriminator.
	Type string `json:"type"`
	// Username for authentication.
	Username *EditableField `json:"username,omitempty"`
	// Password for authentication (concealed-string).
	Password *EditableField `json:"password,omitempty"`
}

// TOTPCredential represents a time-based one-time password (RFC 4226/6238).
type TOTPCredential struct {
	// Credential type discriminator.
	Type string `json:"type"`
	// RFC 4226 shared secret, base32-encoded.
	Secret string `json:"secret"`
	// Time step in seconds (typically 30).
	Period uint8 `json:"period"`
	// Number of digits to display (typically 6).
	Digits uint8 `json:"digits"`
	// Account identifier.
	Username string `json:"username,omitempty"`
	// Hash algorithm ("sha1", "sha256", "sha512").
	Algorithm string `json:"algorithm"`
	// Issuing relying party name.
	Issuer string `json:"issuer,omitempty"`
}

// OTPHashAlgorithm constants for TOTP hash algorithms.
const (
	OTPHashAlgorithmSha1   = "sha1"
	OTPHashAlgorithmSha256 = "sha256"
	OTPHashAlgorithmSha512 = "sha512"
)

// PasskeyCredential represents a WebAuthn private key credential.
// Note: The signature counter must be zero for exported passkeys.
type PasskeyCredential struct {
	// Credential type discriminator.
	Type string `json:"type"`
	// WebAuthn credential ID, base64url-encoded (max 64 bytes decoded).
	CredentialID string `json:"credentialId"`
	// Relying party identifier.
	RpId string `json:"rpId"`
	// Human-readable account identifier.
	Username string `json:"username"`
	// Display name for the account.
	UserDisplayName string `json:"userDisplayName"`
	// Opaque user account identifier, base64url-encoded.
	UserHandle string `json:"userHandle"`
	// PKCS#8 ASN.1 DER formatted private key, base64url-encoded.
	Key string `json:"key"`
	// FIDO2 extensions associated with this credential.
	Fido2Extensions *Fido2Extensions `json:"fido2Extensions,omitempty"`
}

// Fido2Extensions contains optional FIDO2 extension data for a passkey.
type Fido2Extensions struct {
	// PRF or hmac-secret extension credentials.
	HmacCredentials *Fido2HmacCredentials `json:"hmacCredentials,omitempty"`
	// credBlob extension data, base64url-encoded.
	CredBlob string `json:"credBlob,omitempty"`
	// Large blob storage extension data.
	LargeBlob *Fido2LargeBlob `json:"largeBlob,omitempty"`
	// Secure Payment Confirmation capability.
	Payments *bool `json:"payments,omitempty"`
}

// Fido2HmacCredentials contains HMAC-SHA256 credentials for PRF/hmac-secret extensions.
type Fido2HmacCredentials struct {
	// Algorithm identifier (typically "hmac-sha256").
	Algorithm string `json:"algorithm"`
	// Credential for use with user verification, base64url-encoded (32 bytes recommended).
	CredWithUV string `json:"credWithUV"`
	// Credential for use without user verification, base64url-encoded (32 bytes recommended).
	CredWithoutUV string `json:"credWithoutUV"`
}

// Fido2HmacCredentialAlgorithm constants for HMAC credential algorithms.
const (
	Fido2HmacCredentialAlgorithmHmacSha256 = "hmac-sha256"
)

// Fido2LargeBlob contains large blob storage extension data.
type Fido2LargeBlob struct {
	// Original size before DEFLATE compression.
	UncompressedSize uint64 `json:"uncompressedSize"`
	// DEFLATE-compressed data, base64url-encoded.
	Data string `json:"data"`
}

// FileCredential represents a binary file placeholder with metadata.
type FileCredential struct {
	// Credential type discriminator.
	Type string `json:"type"`
	// File identifier used as filename in the archive.
	ID string `json:"id"`
	// Filename with extension.
	Name string `json:"name"`
	// File size in bytes.
	DecryptedSize uint64 `json:"decryptedSize"`
	// SHA-256 hash of the file, base64url-encoded.
	IntegrityHash string `json:"integrityHash"`
}

// CreditCardCredential represents a payment card.
type CreditCardCredential struct {
	// Credential type discriminator.
	Type string `json:"type"`
	// Card number (concealed-string).
	Number *EditableField `json:"number,omitempty"`
	// Cardholder's full name.
	FullName *EditableField `json:"fullName,omitempty"`
	// Card type/brand (e.g., "Visa", "Mastercard").
	CardType *EditableField `json:"cardType,omitempty"`
	// CVV/CVC verification number (concealed-string).
	VerificationNumber *EditableField `json:"verificationNumber,omitempty"`
	// Card PIN (concealed-string).
	PIN *EditableField `json:"pin,omitempty"`
	// Card expiration date (year-month).
	ExpiryDate *EditableField `json:"expiryDate,omitempty"`
	// Card valid-from date (year-month).
	ValidFrom *EditableField `json:"validFrom,omitempty"`
}

// NoteCredential represents a multi-line text note.
type NoteCredential struct {
	// Credential type discriminator.
	Type string `json:"type"`
	// Note content.
	Content *EditableField `json:"content,omitempty"`
}

// Extension represents an extension payload.
// Standard extensions use direct names (e.g., "shared").
// Custom extensions use format: "EXPORTER_RP_ID/EXTENSION_NAME".
type Extension struct {
	// Extension identifier.
	Name string `json:"name"`
	// Extension-specific data (raw JSON for forward compatibility).
	Data json.RawMessage `json:"data,omitempty"`
}

// SharedExtension is the built-in "shared" extension for credential sharing.
type SharedExtension struct {
	// List of entities with access to the shared item/collection.
	Accessors []SharingAccessor `json:"accessors"`
}

// SharingAccessor defines access permissions for a user or group.
type SharingAccessor struct {
	// Type of accessor ("user" or "group").
	Type SharingAccessorType `json:"type"`
	// Target account's base64url-encoded ID.
	AccountID string `json:"accountId"`
	// Username or group name.
	Name string `json:"name"`
	// List of granted permissions.
	Permissions []SharingAccessorPermission `json:"permissions"`
}

// SharingAccessorType defines the type of sharing accessor.
type SharingAccessorType string

// SharingAccessorPermission defines permission levels for sharing.
type SharingAccessorPermission string

// SharingAccessorType constants.
const (
	// Individual user account.
	SharingAccessorTypeUser SharingAccessorType = "user"
	// Group of users.
	SharingAccessorTypeGroup SharingAccessorType = "group"
)

// SharingAccessorPermission constants.
const (
	// View excluding secrets.
	SharingAccessorPermissionRead SharingAccessorPermission = "read"
	// Full read access including secrets.
	SharingAccessorPermissionReadSecret SharingAccessorPermission = "readSecret"
	// Modify entity.
	SharingAccessorPermissionUpdate SharingAccessorPermission = "update"
	// Add sub-entities.
	SharingAccessorPermissionCreate SharingAccessorPermission = "create"
	// Remove sub-entities.
	SharingAccessorPermissionDelete SharingAccessorPermission = "delete"
	// Share with others.
	SharingAccessorPermissionShare SharingAccessorPermission = "share"
	// Full administration.
	SharingAccessorPermissionManage SharingAccessorPermission = "manage"
)
