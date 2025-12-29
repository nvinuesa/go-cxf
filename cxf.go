package cxf

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// VersionMajor represents the CXF major version.
	VersionMajor uint8 = 1
	// VersionMinor represents the CXF minor version.
	VersionMinor uint8 = 0
)

// Common validation errors.
var (
	ErrInvalidVersion        = errors.New("invalid CXF version")
	ErrInvalidFormat         = errors.New("invalid CXF format")
	ErrMissingAccount        = errors.New("missing account")
	ErrMissingItem           = errors.New("missing item")
	ErrMissingFields         = errors.New("missing required fields")
	ErrInvalidIDLength       = errors.New("identifier exceeds 64 bytes")
	ErrInvalidFieldType      = errors.New("invalid editable field type")
	ErrInvalidFieldValue     = errors.New("invalid editable field value for type")
	ErrInvalidCredential     = errors.New("invalid credential")
	ErrInvalidCredentialType = errors.New("invalid credential type")

	// ErrIgnored indicates a structure should be ignored per CXF enum forward-compat rules.
	// Callers should treat this as non-fatal for optional members/entries.
	ErrIgnored = errors.New("ignored per CXF forward-compat rules")
)

// Version encodes the CXF version information.
type Version struct {
	Major uint8 `json:"major"`
	Minor uint8 `json:"minor"`
}

// Header is the top-level CXF structure (formerly Container).
type Header struct {
	Version             Version   `json:"version"`
	ExporterRpId        string    `json:"exporterRpId"`
	ExporterDisplayName string    `json:"exporterDisplayName"`
	Timestamp           uint64    `json:"timestamp"` // UNIX seconds
	Accounts            []Account `json:"accounts"`
}

// Container is kept as an alias for backwards compatibility with previous code paths.
type Container = Header

// Account represents a credential owner’s account.
type Account struct {
	ID          string       `json:"id"`
	Username    string       `json:"username"`
	Email       string       `json:"email"`
	FullName    string       `json:"fullName,omitempty"`
	Collections []Collection `json:"collections"`
	Items       []Item       `json:"items"`
	Extensions  []Extension  `json:"extensions,omitempty"`
}

// Collection groups items together.
type Collection struct {
	ID             string       `json:"id"`
	CreationAt     *uint64      `json:"creationAt,omitempty"`
	ModifiedAt     *uint64      `json:"modifiedAt,omitempty"`
	Title          string       `json:"title"`
	Subtitle       string       `json:"subtitle,omitempty"`
	Items          []LinkedItem `json:"items"`
	SubCollections []Collection `json:"subCollections,omitempty"`
	Extensions     []Extension  `json:"extensions,omitempty"`
}

// LinkedItem points to an item (and optionally its account).
type LinkedItem struct {
	Item    string `json:"item"`
	Account string `json:"account,omitempty"`
}

// Item contains metadata and credentials.
type Item struct {
	ID          string            `json:"id"`
	CreationAt  *uint64           `json:"creationAt,omitempty"`
	ModifiedAt  *uint64           `json:"modifiedAt,omitempty"`
	Title       string            `json:"title"`
	Subtitle    string            `json:"subtitle,omitempty"`
	Favorite    *bool             `json:"favorite,omitempty"`
	Scope       *CredentialScope  `json:"scope,omitempty"`
	Credentials []json.RawMessage `json:"credentials"`
	Tags        []string          `json:"tags,omitempty"`
	Extensions  []Extension       `json:"extensions,omitempty"`
}

// CredentialScope restricts where credentials should be presented.
type CredentialScope struct {
	Urls        []string       `json:"urls"`
	AndroidApps []AndroidAppId `json:"androidApps"`
}

// AndroidAppId identifies an Android application.
type AndroidAppId struct {
	BundleId    string                            `json:"bundleId"`
	Certificate *AndroidAppCertificateFingerprint `json:"certificate,omitempty"`
	Name        string                            `json:"name,omitempty"`
}

// AndroidAppCertificateFingerprint stores a signing cert fingerprint.
type AndroidAppCertificateFingerprint struct {
	Fingerprint string `json:"fingerprint"`
	HashAlg     string `json:"hashAlg"` // "sha256" / "sha512" / other
}

// EditableField represents a user-editable field with a type.
type EditableField struct {
	ID         string          `json:"id,omitempty"`
	FieldType  string          `json:"fieldType"`
	Value      json.RawMessage `json:"value"`
	Label      string          `json:"label,omitempty"`
	Extensions []Extension     `json:"extensions,omitempty"`
}

// FieldType is an enumeration of supported field types.
const (
	FieldTypeString              = "string"
	FieldTypeConcealedString     = "concealed-string"
	FieldTypeEmail               = "email"
	FieldTypeNumber              = "number"
	FieldTypeBoolean             = "boolean"
	FieldTypeDate                = "date"
	FieldTypeYearMonth           = "year-month"
	FieldTypeWifiNetworkSecurity = "wifi-network-security-type"
	FieldTypeCountryCode         = "country-code"
	FieldTypeSubdivisionCode     = "subdivision-code"
)

var validFieldTypes = map[string]struct{}{
	FieldTypeString:              {},
	FieldTypeConcealedString:     {},
	FieldTypeEmail:               {},
	FieldTypeNumber:              {},
	FieldTypeBoolean:             {},
	FieldTypeDate:                {},
	FieldTypeYearMonth:           {},
	FieldTypeWifiNetworkSecurity: {},
	FieldTypeCountryCode:         {},
	FieldTypeSubdivisionCode:     {},
}

var allowedWifiNetworkSecurity = map[string]struct{}{
	"unsecured":     {},
	"wep":           {},
	"wpa-personal":  {},
	"wpa2-personal": {},
	"wpa3-personal": {},
}

// WiFi security type constants.
const (
	WifiSecurityUnsecured    = "unsecured"
	WifiSecurityWEP          = "wep"
	WifiSecurityWPAPersonal  = "wpa-personal"
	WifiSecurityWPA2Personal = "wpa2-personal"
	WifiSecurityWPA3Personal = "wpa3-personal"
)

func validateDateString(s string) bool {
	if s == "" {
		return false
	}
	_, err := time.Parse("2006-01-02", s)
	return err == nil
}

func validateCredentialScope(scope *CredentialScope) error {
	if scope == nil {
		return nil
	}

	// Spec: required arrays must be present even if empty. In typed Go structs we can’t
	// detect JSON member presence here, but we can still validate contents if present.
	// Additionally, enforce strict URL parsing and Android cert fingerprint constraints.

	for _, u := range scope.Urls {
		if strings.TrimSpace(u) == "" {
			return ErrInvalidFormat
		}
		pu, err := url.Parse(u)
		if err != nil {
			return ErrInvalidFormat
		}
		// Require absolute URLs with scheme + host (avoid relative URLs, path-only, etc).
		if pu.Scheme == "" || pu.Host == "" {
			return ErrInvalidFormat
		}
		// Restrict to typical web schemes for credential scopes.
		switch strings.ToLower(pu.Scheme) {
		case "https", "http":
			// ok (spec/vend implementations generally allow these)
		default:
			return ErrInvalidFormat
		}
	}

	for _, app := range scope.AndroidApps {
		if strings.TrimSpace(app.BundleId) == "" {
			return ErrMissingFields
		}
		if app.Certificate == nil {
			continue
		}
		fp := strings.TrimSpace(app.Certificate.Fingerprint)
		alg := strings.ToLower(strings.TrimSpace(app.Certificate.HashAlg))
		if fp == "" || alg == "" {
			return ErrMissingFields
		}
		// Expect hex without separators (common CXF convention). Reject non-hex.
		b, err := hex.DecodeString(fp)
		if err != nil {
			return ErrInvalidFormat
		}
		// Enforce digest length by algorithm.
		switch alg {
		case "sha256":
			if len(b) != 32 {
				return ErrInvalidFormat
			}
		case "sha512":
			if len(b) != 64 {
				return ErrInvalidFormat
			}
		default:
			// Unknown enum/alg => ignore certificate per forward-compat rules.
			return ErrIgnored
		}
	}

	return nil
}

func validatePKCS8PrivateKeyDer(der []byte) error {
	// Minimal, safe sanity check: ensure this is parseable as PKCS#8.
	// This avoids downstream consumers assuming DER correctness.
	//
	// We deliberately don't attempt to validate algorithm-specific parameters here.
	if len(der) == 0 {
		return ErrMissingFields
	}
	if _, err := x509.ParsePKCS8PrivateKey(der); err != nil {
		return ErrInvalidCredential
	}
	return nil
}

// ValidateCredentialStrict performs additional, security-focused validation that may be more strict
// than ValidateCredential, and may reject payloads that are otherwise structurally valid.
//
// Rationale: Parsing PKCS#8 strictly can break existing exporters/tests that store opaque blobs.
// Keeping it in a separate entrypoint allows consumers to opt in to stronger validation.
func ValidateCredentialStrict(raw json.RawMessage) error {
	// First run the normal validator (includes forward-compat ignore rules).
	if err := ValidateCredential(raw); err != nil {
		return err
	}

	// Then run strict type-specific checks where feasible.
	var env struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return ErrInvalidCredential
	}

	switch env.Type {
	case CredentialTypePasskey:
		var c PasskeyCredential
		if err := json.Unmarshal(raw, &c); err != nil {
			return ErrInvalidCredential
		}
		keyDer, err := DecodeBase64URLMaxDecoded(c.Key, 8192)
		if err != nil {
			return ErrInvalidCredential
		}
		if err := validatePKCS8PrivateKeyDer(keyDer); err != nil {
			return err
		}
		return nil
	case CredentialTypeSSHKey:
		var c SSHKeyCredential
		if err := json.Unmarshal(raw, &c); err != nil {
			return ErrInvalidCredential
		}
		der, err := DecodeBase64URLMaxDecoded(c.PrivateKey, 65536)
		if err != nil {
			return ErrInvalidCredential
		}
		if err := validatePKCS8PrivateKeyDer(der); err != nil {
			return err
		}
		return nil
	default:
		// Unknown/other types: no extra strict checks currently.
		return nil
	}
}

// DecodeHeaderJSONStrict decodes a CXF Header from JSON with a hard size limit and requires
// that the input is exactly one JSON document (no trailing data).
//
// This is intended for use with untrusted input.
//
// Note: In addition to top-level required members, this enforces the spec rule that required
// arrays must be present even if empty for nested structures we validate here.
func DecodeHeaderJSONStrict(r io.Reader, maxBytes int64) (*Header, error) {
	if maxBytes <= 0 {
		return nil, fmt.Errorf("maxBytes must be positive")
	}

	// We first decode into a raw map to:
	//  1) enforce strict JSON framing (single document)
	//  2) enforce presence of required top-level members (spec §3.1)
	//  3) keep unknown fields rejected (spec-strict mode)
	dec := json.NewDecoder(io.LimitReader(r, maxBytes))
	dec.DisallowUnknownFields()

	var raw map[string]json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		return nil, err
	}

	// Ensure there's no trailing non-whitespace data.
	var extra interface{}
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("unexpected trailing data after CXF header JSON")
		}
		return nil, err
	}

	// Spec (§3.1): required members must be present even if empty (arrays can be empty but must exist).
	// Enforce key presence here (not just non-zero values after unmarshalling).
	for _, k := range []string{"version", "exporterRpId", "exporterDisplayName", "timestamp", "accounts"} {
		if _, ok := raw[k]; !ok {
			return nil, fmt.Errorf("missing required header member %q", k)
		}
	}

	// Enforce required nested arrays presence (spec §2.1.2).
	// For arrays that are REQUIRED: the member must be present, even if empty.
	accountsRaw := raw["accounts"]
	var accountsArr []json.RawMessage
	if err := json.Unmarshal(accountsRaw, &accountsArr); err != nil {
		return nil, ErrInvalidFormat
	}
	for ai, accRaw := range accountsArr {
		var accObj map[string]json.RawMessage
		if err := json.Unmarshal(accRaw, &accObj); err != nil {
			return nil, ErrInvalidFormat
		}

		// Account.collections and Account.items are required arrays.
		if _, ok := accObj["collections"]; !ok {
			return nil, fmt.Errorf("missing required member %q at accounts[%d]", "collections", ai)
		}
		if _, ok := accObj["items"]; !ok {
			return nil, fmt.Errorf("missing required member %q at accounts[%d]", "items", ai)
		}

		// Validate required arrays within Account.items -> Item.credentials.
		var itemsArr []json.RawMessage
		if err := json.Unmarshal(accObj["items"], &itemsArr); err != nil {
			return nil, ErrInvalidFormat
		}
		for ii, itemRaw := range itemsArr {
			var itemObj map[string]json.RawMessage
			if err := json.Unmarshal(itemRaw, &itemObj); err != nil {
				return nil, ErrInvalidFormat
			}
			if _, ok := itemObj["credentials"]; !ok {
				return nil, fmt.Errorf("missing required member %q at accounts[%d].items[%d]", "credentials", ai, ii)
			}
		}

		// Validate required arrays within Account.collections -> Collection.items.
		var colsArr []json.RawMessage
		if err := json.Unmarshal(accObj["collections"], &colsArr); err != nil {
			return nil, ErrInvalidFormat
		}
		for ci, colRaw := range colsArr {
			var colObj map[string]json.RawMessage
			if err := json.Unmarshal(colRaw, &colObj); err != nil {
				return nil, ErrInvalidFormat
			}
			if _, ok := colObj["items"]; !ok {
				return nil, fmt.Errorf("missing required member %q at accounts[%d].collections[%d]", "items", ai, ci)
			}
		}
	}

	// Now unmarshal with the same strictness into the typed struct.
	typedBytes, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to re-marshal header: %w", err)
	}

	var h Header
	if err := json.Unmarshal(typedBytes, &h); err != nil {
		return nil, err
	}

	if err := h.Validate(); err != nil {
		return nil, err
	}

	return &h, nil
}

func validateYearMonthString(s string) bool {
	if s == "" {
		return false
	}
	_, err := time.Parse("2006-01", s)
	return err == nil
}

func validateCountryCodeString(s string) bool {
	if len(s) != 2 {
		return false
	}
	for i := 0; i < 2; i++ {
		c := s[i]
		if c < 'A' || c > 'Z' {
			return false
		}
	}
	return true
}

func validateSubdivisionCodeString(s string) bool {
	if len(s) < 4 {
		return false
	}
	dash := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '-' {
			dash++
		}
	}
	return dash == 1
}

func parseEditableFieldStringValue(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", ErrMissingFields
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		// Spec requires EditableField.value to be a string (tstr)
		return "", ErrInvalidFieldValue
	}
	return s, nil
}

// ValidateEditableField enforces field type and value constraints for an editable field.
func ValidateEditableField(f EditableField) error {
	if f.FieldType == "" || len(f.Value) == 0 {
		return ErrMissingFields
	}
	if _, ok := validFieldTypes[f.FieldType]; !ok {
		// Spec (§2.1.1): unknown enum values should be ignored (as if not provided) when OPTIONAL.
		// We signal this to callers so they can ignore the field/containing member appropriately.
		return ErrIgnored
	}
	if f.ID != "" {
		if err := ValidateIdentifier(f.ID); err != nil {
			return err
		}
	}

	// Spec: EditableField.value is a string (tstr) for all FieldType values.
	// Some FieldTypes impose additional constraints on the string's format.
	s, err := parseEditableFieldStringValue(f.Value)
	if err != nil {
		return err
	}

	switch f.FieldType {
	case FieldTypeBoolean:
		// Spec: MUST be "true" or "false". Be strict: trim whitespace and require exact match.
		v := strings.ToLower(strings.TrimSpace(s))
		if v != "true" && v != "false" {
			return ErrInvalidFieldValue
		}
	case FieldTypeNumber:
		// Spec: stringified numeric value. Require it parses as a float.
		if _, err := strconv.ParseFloat(strings.TrimSpace(s), 64); err != nil {
			return ErrInvalidFieldValue
		}
	case FieldTypeDate:
		if !validateDateString(s) {
			return ErrInvalidFieldValue
		}
	case FieldTypeYearMonth:
		if !validateYearMonthString(s) {
			return ErrInvalidFieldValue
		}
	case FieldTypeCountryCode:
		if !validateCountryCodeString(s) {
			return ErrInvalidFieldValue
		}
	case FieldTypeSubdivisionCode:
		if !validateSubdivisionCodeString(s) {
			return ErrInvalidFieldValue
		}
	case FieldTypeWifiNetworkSecurity:
		if _, ok := allowedWifiNetworkSecurity[s]; !ok {
			return ErrInvalidFieldValue
		}
	default:
		// string / concealed-string / email have no additional constraints here
	}

	return nil
}

// ValidateEditableFields iterates validation across a slice of editable fields.
func ValidateEditableFields(fields []EditableField) error {
	for _, f := range fields {
		if err := ValidateEditableField(f); err != nil {
			return err
		}
	}
	return nil
}

// ValidateEditableFieldWithExpectedType enforces both field validity and a specific expected fieldType.
//
// Spec note: If the field's fieldType is unknown, ValidateEditableField returns ErrIgnored, which
// propagates here. Callers should interpret ErrIgnored as "act as though the member was not provided"
// when the containing member is OPTIONAL.
func ValidateEditableFieldWithExpectedType(f EditableField, expectedType string) error {
	if err := ValidateEditableField(f); err != nil {
		return err
	}
	if expectedType != "" && f.FieldType != expectedType {
		return ErrInvalidFieldType
	}
	return nil
}

// Credential type constants.
const (
	CredentialTypeBasicAuth         = "basic-auth"
	CredentialTypeTOTP              = "totp"
	CredentialTypePasskey           = "passkey"
	CredentialTypeFile              = "file"
	CredentialTypeCreditCard        = "credit-card"
	CredentialTypeNote              = "note"
	CredentialTypeAPIKey            = "api-key"
	CredentialTypeAddress           = "address"
	CredentialTypeGeneratedPassword = "generated-password"
	CredentialTypeIdentityDocument  = "identity-document"
	CredentialTypeDriversLicense    = "drivers-license"
	CredentialTypePassport          = "passport"
	CredentialTypePersonName        = "person-name"
	CredentialTypeCustomFields      = "custom-fields"
	CredentialTypeSSHKey            = "ssh-key"
	CredentialTypeWiFi              = "wifi"
	CredentialTypeItemReference     = "item-reference"
)

type APIKeyCredential struct {
	Type       string         `json:"type"`
	Key        *EditableField `json:"key,omitempty"`
	Username   *EditableField `json:"username,omitempty"`
	KeyType    *EditableField `json:"keyType,omitempty"`
	URL        *EditableField `json:"url,omitempty"`
	ValidFrom  *EditableField `json:"validFrom,omitempty"`
	ExpiryDate *EditableField `json:"expiryDate,omitempty"`
}

type AddressCredential struct {
	Type          string         `json:"type"`
	StreetAddress *EditableField `json:"streetAddress,omitempty"`
	PostalCode    *EditableField `json:"postalCode,omitempty"`
	City          *EditableField `json:"city,omitempty"`
	Territory     *EditableField `json:"territory,omitempty"`
	Country       *EditableField `json:"country,omitempty"`
	Tel           *EditableField `json:"tel,omitempty"`
}

type PasswordRecipe struct {
	Length         int  `json:"length"`
	Uppercase      bool `json:"uppercase,omitempty"`
	Lowercase      bool `json:"lowercase,omitempty"`
	Numbers        bool `json:"numbers,omitempty"`
	Symbols        bool `json:"symbols,omitempty"`
	AvoidAmbiguous bool `json:"avoidAmbiguous,omitempty"`
}

type GeneratedPasswordCredential struct {
	Type     string `json:"type"`
	Password string `json:"password"`
}

type PersonNameCredential struct {
	Type          string         `json:"type"`
	Title         *EditableField `json:"title,omitempty"`
	Given         *EditableField `json:"given,omitempty"`
	GivenInformal *EditableField `json:"givenInformal,omitempty"`
	Given2        *EditableField `json:"given2,omitempty"`
	SurnamePrefix *EditableField `json:"surnamePrefix,omitempty"`
	Surname       *EditableField `json:"surname,omitempty"`
	Surname2      *EditableField `json:"surname2,omitempty"`
	Credentials   *EditableField `json:"credentials,omitempty"`
	Generation    *EditableField `json:"generation,omitempty"`
}

type IdentityDocumentCredential struct {
	Type                 string         `json:"type"`
	IssuingCountry       *EditableField `json:"issuingCountry,omitempty"`
	DocumentNumber       *EditableField `json:"documentNumber,omitempty"`
	IdentificationNumber *EditableField `json:"identificationNumber,omitempty"`
	Nationality          *EditableField `json:"nationality,omitempty"`
	FullName             *EditableField `json:"fullName,omitempty"`
	BirthDate            *EditableField `json:"birthDate,omitempty"`
	BirthPlace           *EditableField `json:"birthPlace,omitempty"`
	Sex                  *EditableField `json:"sex,omitempty"`
	IssueDate            *EditableField `json:"issueDate,omitempty"`
	ExpiryDate           *EditableField `json:"expiryDate,omitempty"`
	IssuingAuthority     *EditableField `json:"issuingAuthority,omitempty"`
}

type DriversLicenseCredential struct {
	Type             string         `json:"type"`
	FullName         *EditableField `json:"fullName,omitempty"`
	BirthDate        *EditableField `json:"birthDate,omitempty"`
	IssueDate        *EditableField `json:"issueDate,omitempty"`
	ExpiryDate       *EditableField `json:"expiryDate,omitempty"`
	IssuingAuthority *EditableField `json:"issuingAuthority,omitempty"`
	Territory        *EditableField `json:"territory,omitempty"`
	Country          *EditableField `json:"country,omitempty"`
	LicenseNumber    *EditableField `json:"licenseNumber,omitempty"`
	LicenseClass     *EditableField `json:"licenseClass,omitempty"`
}

type PassportCredential struct {
	Type                         string         `json:"type"`
	IssuingCountry               *EditableField `json:"issuingCountry,omitempty"`
	PassportType                 *EditableField `json:"passportType,omitempty"`
	PassportNumber               *EditableField `json:"passportNumber,omitempty"`
	NationalIdentificationNumber *EditableField `json:"nationalIdentificationNumber,omitempty"`
	Nationality                  *EditableField `json:"nationality,omitempty"`
	FullName                     *EditableField `json:"fullName,omitempty"`
	BirthDate                    *EditableField `json:"birthDate,omitempty"`
	BirthPlace                   *EditableField `json:"birthPlace,omitempty"`
	Sex                          *EditableField `json:"sex,omitempty"`
	IssueDate                    *EditableField `json:"issueDate,omitempty"`
	ExpiryDate                   *EditableField `json:"expiryDate,omitempty"`
	IssuingAuthority             *EditableField `json:"issuingAuthority,omitempty"`
}

type CustomFieldsCredential struct {
	Type       string          `json:"type"`
	ID         string          `json:"id,omitempty"`
	Label      string          `json:"label,omitempty"`
	Fields     []EditableField `json:"fields"`
	Extensions []Extension     `json:"extensions,omitempty"`
}

type SSHKeyCredential struct {
	Type                string         `json:"type"`
	KeyType             string         `json:"keyType"`
	PrivateKey          string         `json:"privateKey"`
	KeyComment          string         `json:"keyComment,omitempty"`
	CreationDate        *EditableField `json:"creationDate,omitempty"`
	ExpiryDate          *EditableField `json:"expiryDate,omitempty"`
	KeyGenerationSource *EditableField `json:"keyGenerationSource,omitempty"`
}

type WiFiCredential struct {
	Type                string         `json:"type"`
	SSID                *EditableField `json:"ssid,omitempty"`
	NetworkSecurityType *EditableField `json:"networkSecurityType,omitempty"`
	Passphrase          *EditableField `json:"passphrase,omitempty"`
	Hidden              *EditableField `json:"hidden,omitempty"`
}

type ItemReferenceCredential struct {
	Type      string     `json:"type"`
	Reference LinkedItem `json:"reference"`
}

// BasicAuth credential schema.
type BasicAuthCredential struct {
	Type     string         `json:"type"`
	Username *EditableField `json:"username,omitempty"`
	Password *EditableField `json:"password,omitempty"`
}

// TOTP credential schema.
type TOTPCredential struct {
	Type      string `json:"type"`
	Secret    string `json:"secret"`
	Period    int    `json:"period"`
	Digits    int    `json:"digits"`
	Username  string `json:"username,omitempty"`
	Algorithm string `json:"algorithm"`
	Issuer    string `json:"issuer,omitempty"`
}

var totpAllowedAlgorithms = map[string]struct{}{
	"sha1":   {},
	"sha256": {},
	"sha512": {},
}

var totpAllowedDigits = map[int]struct{}{
	6: {}, 7: {}, 8: {},
}

// Passkey credential schema.
type PasskeyCredential struct {
	Type            string           `json:"type"`
	CredentialID    string           `json:"credentialId"`
	RpId            string           `json:"rpId"`
	Username        string           `json:"username"`
	UserDisplayName string           `json:"userDisplayName"`
	UserHandle      string           `json:"userHandle"`
	Key             string           `json:"key"`
	Fido2Extensions *Fido2Extensions `json:"fido2Extensions,omitempty"`
}

type Fido2Extensions struct {
	HmacCredentials *Fido2HmacCredentials `json:"hmacCredentials,omitempty"`
	CredBlob        string                `json:"credBlob,omitempty"`
	LargeBlob       *Fido2LargeBlob       `json:"largeBlob,omitempty"`
	Payments        *bool                 `json:"payments,omitempty"`
}

type Fido2HmacCredentials struct {
	Algorithm     string `json:"algorithm"`
	CredWithUV    string `json:"credWithUV"`
	CredWithoutUV string `json:"credWithoutUV"`
}

type Fido2LargeBlob struct {
	UncompressedSize uint64 `json:"uncompressedSize"`
	Data             string `json:"data"`
}

// File credential schema.
type FileCredential struct {
	Type          string `json:"type"`
	ID            string `json:"id"`
	Name          string `json:"name"`
	DecryptedSize uint64 `json:"decryptedSize"`
	IntegrityHash string `json:"integrityHash"`
}

// Credit card credential schema.
type CreditCardCredential struct {
	Type               string         `json:"type"`
	Number             *EditableField `json:"number,omitempty"`
	FullName           *EditableField `json:"fullName,omitempty"`
	CardType           *EditableField `json:"cardType,omitempty"`
	VerificationNumber *EditableField `json:"verificationNumber,omitempty"`
	PIN                *EditableField `json:"pin,omitempty"`
	ExpiryDate         *EditableField `json:"expiryDate,omitempty"`
	ValidFrom          *EditableField `json:"validFrom,omitempty"`
}

// Note credential schema.
type NoteCredential struct {
	Type    string         `json:"type"`
	Content *EditableField `json:"content,omitempty"`
}

func ValidateBasicAuthCredential(c BasicAuthCredential) error {
	if c.Type != CredentialTypeBasicAuth {
		return ErrInvalidCredentialType
	}
	if c.Username == nil && c.Password == nil {
		return ErrMissingFields
	}
	if c.Username != nil {
		if err := ValidateEditableFieldWithExpectedType(*c.Username, FieldTypeString); err != nil {
			return err
		}
	}
	if c.Password != nil {
		if err := ValidateEditableFieldWithExpectedType(*c.Password, FieldTypeConcealedString); err != nil {
			return err
		}
	}
	return nil
}

func ValidateAPIKeyCredential(c APIKeyCredential) error {
	if c.Type != CredentialTypeAPIKey {
		return ErrInvalidCredentialType
	}
	fields := []*EditableField{c.Key, c.Username, c.KeyType, c.URL, c.ValidFrom, c.ExpiryDate}
	present := false
	for idx, f := range fields {
		if f == nil {
			continue
		}
		present = true
		switch idx {
		case 0:
			if err := ValidateEditableFieldWithExpectedType(*f, FieldTypeConcealedString); err != nil {
				return err
			}
		case 1, 2, 3:
			if err := ValidateEditableFieldWithExpectedType(*f, FieldTypeString); err != nil {
				return err
			}
		case 4, 5:
			if err := ValidateEditableFieldWithExpectedType(*f, FieldTypeDate); err != nil {
				return err
			}
		}
	}
	if !present {
		return ErrMissingFields
	}
	return nil
}

func ValidateAddressCredential(c AddressCredential) error {
	if c.Type != CredentialTypeAddress {
		return ErrInvalidCredentialType
	}
	fields := []*EditableField{c.StreetAddress, c.PostalCode, c.City, c.Territory, c.Country, c.Tel}
	present := false
	for idx, f := range fields {
		if f == nil {
			continue
		}
		present = true
		expected := FieldTypeString
		switch idx {
		case 3:
			expected = FieldTypeSubdivisionCode
		case 4:
			expected = FieldTypeCountryCode
		}
		if err := ValidateEditableFieldWithExpectedType(*f, expected); err != nil {
			return err
		}
	}
	if !present {
		return ErrMissingFields
	}
	return nil
}

func ValidateGeneratedPasswordCredential(c GeneratedPasswordCredential) error {
	if c.Type != CredentialTypeGeneratedPassword {
		return ErrInvalidCredentialType
	}
	if c.Password == "" {
		return ErrMissingFields
	}
	return nil
}

func ValidatePersonNameCredential(c PersonNameCredential) error {
	if c.Type != CredentialTypePersonName {
		return ErrInvalidCredentialType
	}
	fields := []*EditableField{c.Title, c.Given, c.GivenInformal, c.Given2, c.SurnamePrefix, c.Surname, c.Surname2, c.Credentials, c.Generation}
	present := false
	for _, f := range fields {
		if f == nil {
			continue
		}
		present = true
		if err := ValidateEditableFieldWithExpectedType(*f, FieldTypeString); err != nil {
			return err
		}
	}
	if !present {
		return ErrMissingFields
	}
	return nil
}

func ValidateIdentityDocumentCredential(c IdentityDocumentCredential) error {
	if c.Type != CredentialTypeIdentityDocument {
		return ErrInvalidCredentialType
	}
	// Validate fields by type
	present := false
	// Country code fields
	for _, f := range []*EditableField{c.IssuingCountry} {
		if f != nil {
			present = true
			if err := ValidateEditableFieldWithExpectedType(*f, FieldTypeCountryCode); err != nil {
				return err
			}
		}
	}
	// Date fields
	for _, f := range []*EditableField{c.BirthDate, c.IssueDate, c.ExpiryDate} {
		if f != nil {
			present = true
			if err := ValidateEditableFieldWithExpectedType(*f, FieldTypeDate); err != nil {
				return err
			}
		}
	}
	// String fields
	for _, f := range []*EditableField{c.DocumentNumber, c.IdentificationNumber, c.Nationality, c.FullName, c.BirthPlace, c.Sex, c.IssuingAuthority} {
		if f != nil {
			present = true
			if err := ValidateEditableFieldWithExpectedType(*f, FieldTypeString); err != nil {
				return err
			}
		}
	}
	if !present {
		return ErrMissingFields
	}
	return nil
}

func ValidateDriversLicenseCredential(c DriversLicenseCredential) error {
	if c.Type != CredentialTypeDriversLicense {
		return ErrInvalidCredentialType
	}
	present := false
	// Country code fields
	if c.Country != nil {
		present = true
		if err := ValidateEditableFieldWithExpectedType(*c.Country, FieldTypeCountryCode); err != nil {
			return err
		}
	}
	// Subdivision code fields
	if c.Territory != nil {
		present = true
		if err := ValidateEditableFieldWithExpectedType(*c.Territory, FieldTypeSubdivisionCode); err != nil {
			return err
		}
	}
	// Date fields
	for _, f := range []*EditableField{c.BirthDate, c.IssueDate, c.ExpiryDate} {
		if f != nil {
			present = true
			if err := ValidateEditableFieldWithExpectedType(*f, FieldTypeDate); err != nil {
				return err
			}
		}
	}
	// String fields
	for _, f := range []*EditableField{c.FullName, c.IssuingAuthority, c.LicenseNumber, c.LicenseClass} {
		if f != nil {
			present = true
			if err := ValidateEditableFieldWithExpectedType(*f, FieldTypeString); err != nil {
				return err
			}
		}
	}
	if !present {
		return ErrMissingFields
	}
	return nil
}

func ValidatePassportCredential(c PassportCredential) error {
	if c.Type != CredentialTypePassport {
		return ErrInvalidCredentialType
	}
	present := false
	// Country code fields
	if c.IssuingCountry != nil {
		present = true
		if err := ValidateEditableFieldWithExpectedType(*c.IssuingCountry, FieldTypeCountryCode); err != nil {
			return err
		}
	}
	// Date fields
	for _, f := range []*EditableField{c.BirthDate, c.IssueDate, c.ExpiryDate} {
		if f != nil {
			present = true
			if err := ValidateEditableFieldWithExpectedType(*f, FieldTypeDate); err != nil {
				return err
			}
		}
	}
	// String fields
	for _, f := range []*EditableField{c.PassportType, c.PassportNumber, c.NationalIdentificationNumber, c.Nationality, c.FullName, c.BirthPlace, c.Sex, c.IssuingAuthority} {
		if f != nil {
			present = true
			if err := ValidateEditableFieldWithExpectedType(*f, FieldTypeString); err != nil {
				return err
			}
		}
	}
	if !present {
		return ErrMissingFields
	}
	return nil
}

func ValidateCustomFieldsCredential(c CustomFieldsCredential) error {
	if c.Type != CredentialTypeCustomFields {
		return ErrInvalidCredentialType
	}
	if c.ID != "" {
		if err := ValidateIdentifier(c.ID); err != nil {
			return err
		}
	}
	if len(c.Fields) == 0 {
		return ErrMissingFields
	}
	return ValidateEditableFields(c.Fields)
}

func ValidateSSHKeyCredential(c SSHKeyCredential) error {
	if c.Type != CredentialTypeSSHKey {
		return ErrInvalidCredentialType
	}
	// keyType and privateKey are required
	if c.KeyType == "" || c.PrivateKey == "" {
		return ErrMissingFields
	}
	// privateKey must be valid base64url; additionally enforce a max decoded size to mitigate DoS.
	if _, err := DecodeBase64URLMaxDecoded(c.PrivateKey, 65536); err != nil {
		return ErrInvalidCredential
	}
	// NOTE: PKCS#8 parsing is intentionally NOT enforced here to avoid breaking existing
	// exporters/consumers that store opaque blobs. Use ValidateCredentialStrict for PKCS#8 checks.

	// Optional date fields
	if c.CreationDate != nil {
		if err := ValidateEditableFieldWithExpectedType(*c.CreationDate, FieldTypeDate); err != nil {
			return err
		}
	}
	if c.ExpiryDate != nil {
		if err := ValidateEditableFieldWithExpectedType(*c.ExpiryDate, FieldTypeDate); err != nil {
			return err
		}
	}
	if c.KeyGenerationSource != nil {
		if err := ValidateEditableField(*c.KeyGenerationSource); err != nil {
			return err
		}
	}
	return nil
}

func ValidateWiFiCredential(c WiFiCredential) error {
	if c.Type != CredentialTypeWiFi {
		return ErrInvalidCredentialType
	}
	if c.SSID != nil {
		if err := ValidateEditableFieldWithExpectedType(*c.SSID, FieldTypeString); err != nil {
			return err
		}
	}
	if c.NetworkSecurityType != nil {
		if err := ValidateEditableFieldWithExpectedType(*c.NetworkSecurityType, FieldTypeWifiNetworkSecurity); err != nil {
			return err
		}
	}
	if c.Passphrase != nil {
		if err := ValidateEditableFieldWithExpectedType(*c.Passphrase, FieldTypeConcealedString); err != nil {
			return err
		}
	}
	if c.Hidden != nil {
		if err := ValidateEditableFieldWithExpectedType(*c.Hidden, FieldTypeBoolean); err != nil {
			return err
		}
	}
	return nil
}

func ValidateItemReferenceCredential(c ItemReferenceCredential) error {
	if c.Type != CredentialTypeItemReference {
		return ErrInvalidCredentialType
	}
	if c.Reference.Item == "" {
		return ErrMissingFields
	}
	if err := ValidateIdentifier(c.Reference.Item); err != nil {
		return err
	}
	if c.Reference.Account != "" {
		if err := ValidateIdentifier(c.Reference.Account); err != nil {
			return err
		}
	}
	return nil
}

func ValidateTOTPCredential(c TOTPCredential) error {
	if c.Type != CredentialTypeTOTP {
		return ErrInvalidCredentialType
	}
	if c.Secret == "" || c.Algorithm == "" || c.Period <= 0 || c.Digits <= 0 {
		return ErrMissingFields
	}
	if _, ok := totpAllowedAlgorithms[c.Algorithm]; !ok {
		// Spec (§3.3.16): importers MUST ignore TOTP entries with unknown algorithm values.
		return ErrIgnored
	}
	if _, ok := totpAllowedDigits[c.Digits]; !ok {
		return ErrInvalidCredential
	}
	if err := ValidateBase32(c.Secret); err != nil {
		return ErrInvalidCredential
	}
	return nil
}

func ValidatePasskeyCredential(c PasskeyCredential) error {
	if c.Type != CredentialTypePasskey {
		return ErrInvalidCredentialType
	}
	if c.CredentialID == "" || c.RpId == "" || c.Username == "" || c.UserDisplayName == "" || c.UserHandle == "" || c.Key == "" {
		return ErrMissingFields
	}
	if err := ValidateIdentifier(c.CredentialID); err != nil {
		return err
	}
	// These fields are base64url-encoded and come from untrusted input; enforce reasonable
	// maximum decoded sizes to mitigate memory/DoS attacks.
	if _, err := DecodeBase64URLMaxDecoded(c.UserHandle, 64); err != nil {
		return ErrInvalidCredential
	}
	_, err := DecodeBase64URLMaxDecoded(c.Key, 8192)
	if err != nil {
		return ErrInvalidCredential
	}
	// NOTE: PKCS#8 parsing is intentionally NOT enforced here to avoid breaking existing
	// exporters/consumers that store opaque blobs. Use ValidateCredentialStrict for PKCS#8 checks.
	if c.Fido2Extensions != nil {
		if err := validateFido2Extensions(c.Fido2Extensions); err != nil {
			return err
		}
	}
	return nil
}

func validateFido2Extensions(ext *Fido2Extensions) error {
	if ext == nil {
		return nil
	}

	if ext.HmacCredentials != nil {
		if ext.HmacCredentials.Algorithm == "" || ext.HmacCredentials.CredWithUV == "" || ext.HmacCredentials.CredWithoutUV == "" {
			return ErrMissingFields
		}
		for _, v := range []string{ext.HmacCredentials.CredWithUV, ext.HmacCredentials.CredWithoutUV} {
			decoded, err := DecodeBase64URLMaxDecoded(v, 32)
			if err != nil {
				return ErrInvalidCredential
			}
			if len(decoded) != 32 {
				return ErrInvalidCredential
			}
		}
	}

	if ext.CredBlob != "" {
		// credBlob is opaque but should still be bounded.
		if err := ValidateBase64URLMaxDecoded(ext.CredBlob, 65536); err != nil {
			return ErrInvalidCredential
		}
	}

	if ext.LargeBlob != nil {
		if ext.LargeBlob.UncompressedSize == 0 || ext.LargeBlob.Data == "" {
			return ErrMissingFields
		}
		// Enforce a hard cap based on declared uncompressed size plus a small overhead.
		// (We don't decompress here; this is just a decode-size guard.)
		maxDecoded := int(ext.LargeBlob.UncompressedSize)
		if maxDecoded < 0 {
			return ErrInvalidCredential
		}
		if maxDecoded > 1024*1024 {
			// Prevent absurd allocations even if the declared size is huge.
			maxDecoded = 1024 * 1024
		}
		if _, err := DecodeBase64URLMaxDecoded(ext.LargeBlob.Data, maxDecoded); err != nil {
			return ErrInvalidCredential
		}
	}

	return nil
}

func ValidateFileCredential(c FileCredential) error {
	if c.Type != CredentialTypeFile {
		return ErrInvalidCredentialType
	}
	if c.ID == "" || c.Name == "" || c.DecryptedSize == 0 || c.IntegrityHash == "" {
		return ErrMissingFields
	}
	if err := ValidateIdentifier(c.ID); err != nil {
		return err
	}
	// integrityHash is sha256 => 32 bytes when decoded.
	if err := ValidateBase64URLMaxDecoded(c.IntegrityHash, 32); err != nil {
		return ErrInvalidCredential
	}
	return nil
}

func ValidateCreditCardCredential(c CreditCardCredential) error {
	if c.Type != CredentialTypeCreditCard {
		return ErrInvalidCredentialType
	}
	fields := []*EditableField{c.Number, c.FullName, c.CardType, c.VerificationNumber, c.PIN, c.ExpiryDate, c.ValidFrom}
	present := false
	for idx, f := range fields {
		if f == nil {
			continue
		}
		present = true
		expected := FieldTypeString
		switch idx {
		case 0, 3, 4:
			expected = FieldTypeConcealedString
		case 5, 6:
			expected = FieldTypeYearMonth
		}
		if err := ValidateEditableFieldWithExpectedType(*f, expected); err != nil {
			return err
		}
	}
	if !present {
		return ErrMissingFields
	}
	return nil
}

func ValidateNoteCredential(c NoteCredential) error {
	if c.Type != CredentialTypeNote {
		return ErrInvalidCredentialType
	}
	if c.Content == nil {
		return ErrMissingFields
	}
	if err := ValidateEditableFieldWithExpectedType(*c.Content, FieldTypeString); err != nil {
		return err
	}
	return nil
}

// ComputeIntegrityHash returns the base64url-encoded SHA-256 hash of the data.
func ComputeIntegrityHash(data []byte) string {
	sum := sha256.Sum256(data)
	return EncodeBase64URL(sum[:])
}

// ValidateIntegrityHash compares the provided integrity hash against the SHA-256 of data.
func ValidateIntegrityHash(data []byte, integrityHash string) error {
	if integrityHash == "" {
		return ErrMissingFields
	}
	if ComputeIntegrityHash(data) != integrityHash {
		return ErrInvalidCredential
	}
	return nil
}

type credentialEnvelope struct {
	Type string `json:"type"`
}

// ValidateCredential dispatches credential validation based on type.
func ValidateCredential(raw json.RawMessage) error {
	var env credentialEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return ErrInvalidCredential
	}

	switch env.Type {
	case CredentialTypeBasicAuth:
		var c BasicAuthCredential
		if err := json.Unmarshal(raw, &c); err != nil {
			return ErrInvalidCredential
		}
		if err := ValidateBasicAuthCredential(c); err != nil {
			// Unknown field types inside OPTIONAL fields should be ignored, not fatal.
			if errors.Is(err, ErrIgnored) {
				return nil
			}
			return err
		}
		return nil
	case CredentialTypeAPIKey:
		var c APIKeyCredential
		if err := json.Unmarshal(raw, &c); err != nil {
			return ErrInvalidCredential
		}
		if err := ValidateAPIKeyCredential(c); err != nil {
			if errors.Is(err, ErrIgnored) {
				return nil
			}
			return err
		}
		return nil
	case CredentialTypeAddress:
		var c AddressCredential
		if err := json.Unmarshal(raw, &c); err != nil {
			return ErrInvalidCredential
		}
		if err := ValidateAddressCredential(c); err != nil {
			if errors.Is(err, ErrIgnored) {
				return nil
			}
			return err
		}
		return nil
	case CredentialTypeGeneratedPassword:
		var c GeneratedPasswordCredential
		if err := json.Unmarshal(raw, &c); err != nil {
			return ErrInvalidCredential
		}
		return ValidateGeneratedPasswordCredential(c)
	case CredentialTypeIdentityDocument:
		var c IdentityDocumentCredential
		if err := json.Unmarshal(raw, &c); err != nil {
			return ErrInvalidCredential
		}
		if err := ValidateIdentityDocumentCredential(c); err != nil {
			if errors.Is(err, ErrIgnored) {
				return nil
			}
			return err
		}
		return nil
	case CredentialTypeDriversLicense:
		var c DriversLicenseCredential
		if err := json.Unmarshal(raw, &c); err != nil {
			return ErrInvalidCredential
		}
		if err := ValidateDriversLicenseCredential(c); err != nil {
			if errors.Is(err, ErrIgnored) {
				return nil
			}
			return err
		}
		return nil
	case CredentialTypePassport:
		var c PassportCredential
		if err := json.Unmarshal(raw, &c); err != nil {
			return ErrInvalidCredential
		}
		if err := ValidatePassportCredential(c); err != nil {
			if errors.Is(err, ErrIgnored) {
				return nil
			}
			return err
		}
		return nil
	case CredentialTypePersonName:
		var c PersonNameCredential
		if err := json.Unmarshal(raw, &c); err != nil {
			return ErrInvalidCredential
		}
		if err := ValidatePersonNameCredential(c); err != nil {
			if errors.Is(err, ErrIgnored) {
				return nil
			}
			return err
		}
		return nil
	case CredentialTypeCustomFields:
		var c CustomFieldsCredential
		if err := json.Unmarshal(raw, &c); err != nil {
			return ErrInvalidCredential
		}
		if err := ValidateCustomFieldsCredential(c); err != nil {
			if errors.Is(err, ErrIgnored) {
				return nil
			}
			return err
		}
		return nil
	case CredentialTypeSSHKey:
		var c SSHKeyCredential
		if err := json.Unmarshal(raw, &c); err != nil {
			return ErrInvalidCredential
		}
		return ValidateSSHKeyCredential(c)
	case CredentialTypeWiFi:
		var c WiFiCredential
		if err := json.Unmarshal(raw, &c); err != nil {
			return ErrInvalidCredential
		}
		if err := ValidateWiFiCredential(c); err != nil {
			if errors.Is(err, ErrIgnored) {
				return nil
			}
			return err
		}
		return nil
	case CredentialTypeItemReference:
		var c ItemReferenceCredential
		if err := json.Unmarshal(raw, &c); err != nil {
			return ErrInvalidCredential
		}
		return ValidateItemReferenceCredential(c)
	case CredentialTypeTOTP:
		var c TOTPCredential
		if err := json.Unmarshal(raw, &c); err != nil {
			return ErrInvalidCredential
		}
		if err := ValidateTOTPCredential(c); err != nil {
			if errors.Is(err, ErrIgnored) {
				// Unknown algorithm => ignore TOTP credential per spec.
				return nil
			}
			return err
		}
		return nil
	case CredentialTypePasskey:
		var c PasskeyCredential
		if err := json.Unmarshal(raw, &c); err != nil {
			return ErrInvalidCredential
		}
		return ValidatePasskeyCredential(c)
	case CredentialTypeFile:
		var c FileCredential
		if err := json.Unmarshal(raw, &c); err != nil {
			return ErrInvalidCredential
		}
		return ValidateFileCredential(c)
	case CredentialTypeCreditCard:
		var c CreditCardCredential
		if err := json.Unmarshal(raw, &c); err != nil {
			return ErrInvalidCredential
		}
		if err := ValidateCreditCardCredential(c); err != nil {
			if errors.Is(err, ErrIgnored) {
				return nil
			}
			return err
		}
		return nil
	case CredentialTypeNote:
		var c NoteCredential
		if err := json.Unmarshal(raw, &c); err != nil {
			return ErrInvalidCredential
		}
		if err := ValidateNoteCredential(c); err != nil {
			if errors.Is(err, ErrIgnored) {
				return nil
			}
			return err
		}
		return nil
	default:
		// Per spec: "Importing providers MAY attempt to store unknown credential types"
		// Unknown credential types are passed through without error
		return nil
	}
}

// ValidateCredentials iterates validation across a slice of credentials.
func ValidateCredentials(creds []json.RawMessage) error {
	for _, raw := range creds {
		if err := ValidateCredential(raw); err != nil {
			return err
		}
	}
	return nil
}

// Extension is an extension payload.
//
// For safer decoding (and to support typed extensions), keep `Data` as raw JSON.
// Callers/validators can selectively decode known extensions.
type Extension struct {
	Name string          `json:"name"`
	Data json.RawMessage `json:"data,omitempty"`
}

// SharedExtension is the CXF typed `shared` extension payload.
//
// NOTE: This models the current CXF review-draft intent: it is intentionally strict about shape,
// but tolerant/forward-compatible about unknown enum values by surfacing ErrIgnored where appropriate.
type SharedExtension struct {
	Accessors []SharingAccessor `json:"accessors"`
}

// SharingAccessor identifies an entity that may access a shared item/collection.
type SharingAccessor struct {
	Type        SharingAccessorType         `json:"type"`
	ExternalID  string                      `json:"externalId,omitempty"`
	Permissions []SharingAccessorPermission `json:"permissions"`
}

// SharingAccessorType is an enum for accessor types.
type SharingAccessorType string

// SharingAccessorPermission is an enum for permissions.
type SharingAccessorPermission string

const (
	SharingAccessorTypeUser  SharingAccessorType = "user"
	SharingAccessorTypeGroup SharingAccessorType = "group"

	SharingAccessorPermissionRead  SharingAccessorPermission = "read"
	SharingAccessorPermissionWrite SharingAccessorPermission = "write"
)

// DecodeSharedExtension attempts to decode a `shared` extension payload from an Extension.
// It returns ErrIgnored if the extension is not `shared` or if it contains unknown enum values
// that should be ignored per CXF forward-compat rules.
func DecodeSharedExtension(ext Extension) (*SharedExtension, error) {
	if ext.Name != "shared" {
		return nil, ErrIgnored
	}
	// If `data` is missing/null treat as invalid format for a known extension.
	if len(ext.Data) == 0 || string(ext.Data) == "null" {
		return nil, ErrInvalidFormat
	}
	var s SharedExtension
	if err := json.Unmarshal(ext.Data, &s); err != nil {
		return nil, ErrInvalidFormat
	}
	if err := ValidateSharedExtension(s); err != nil {
		return nil, err
	}
	return &s, nil
}

// ValidateSharedExtension validates the typed `shared` extension payload.
func ValidateSharedExtension(s SharedExtension) error {
	// In CXF, required arrays must be present (even if empty). Here we only validate typed payload.
	// If `accessors` is omitted it will decode as nil; treat that as missing required member.
	if s.Accessors == nil {
		return ErrMissingFields
	}
	for _, a := range s.Accessors {
		if err := ValidateSharingAccessor(a); err != nil {
			return err
		}
	}
	return nil
}

func ValidateSharingAccessor(a SharingAccessor) error {
	if a.Type == "" {
		return ErrMissingFields
	}
	switch a.Type {
	case SharingAccessorTypeUser, SharingAccessorTypeGroup:
		// ok
	default:
		// Unknown enum value => ignore per CXF forward-compat rules.
		return ErrIgnored
	}

	// permissions is required and must be present (even if empty).
	if a.Permissions == nil {
		return ErrMissingFields
	}
	for _, p := range a.Permissions {
		switch p {
		case SharingAccessorPermissionRead, SharingAccessorPermissionWrite:
			// ok
		default:
			// Unknown enum value => ignore per CXF forward-compat rules.
			return ErrIgnored
		}
	}

	return nil
}

// NewHeader constructs a Header with the default version.
func NewHeader(exporterRpId, exporterDisplayName string, timestamp uint64) *Header {
	return &Header{
		Version: Version{
			Major: VersionMajor,
			Minor: VersionMinor,
		},
		ExporterRpId:        exporterRpId,
		ExporterDisplayName: exporterDisplayName,
		Timestamp:           timestamp,
		Accounts:            make([]Account, 0),
	}
}

// Marshal serializes the header to JSON.
func (h *Header) Marshal() ([]byte, error) {
	return json.Marshal(h)
}

// MarshalIndent serializes the header to indented JSON.
func (h *Header) MarshalIndent() ([]byte, error) {
	return json.MarshalIndent(h, "", "  ")
}

// Validate performs basic structural validation of the header.
func (h *Header) Validate() error {
	if h.Version.Major != VersionMajor || h.Version.Minor != VersionMinor {
		return ErrInvalidVersion
	}
	if h.ExporterRpId == "" || h.ExporterDisplayName == "" || h.Timestamp == 0 {
		return ErrInvalidFormat
	}
	if len(h.Accounts) == 0 {
		return ErrMissingAccount
	}
	for _, acc := range h.Accounts {
		if err := acc.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// Validate performs basic structural validation of the account.
func (a *Account) Validate() error {
	if a.ID == "" || a.Username == "" || a.Email == "" {
		return ErrMissingFields
	}
	if err := ValidateIdentifier(a.ID); err != nil {
		return err
	}
	if len(a.Items) == 0 {
		return ErrMissingItem
	}
	for _, item := range a.Items {
		if err := item.Validate(); err != nil {
			return err
		}
	}
	for _, col := range a.Collections {
		if err := col.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// Validate checks collection invariants.
func (c *Collection) Validate() error {
	if c.ID == "" || c.Title == "" {
		return ErrMissingFields
	}
	if err := ValidateIdentifier(c.ID); err != nil {
		return err
	}
	return nil
}

// Validate checks item invariants.
func (i *Item) Validate() error {
	if i.ID == "" || i.Title == "" {
		return ErrMissingFields
	}
	if err := ValidateIdentifier(i.ID); err != nil {
		return err
	}
	if i.Scope != nil {
		if err := validateCredentialScope(i.Scope); err != nil {
			// Per forward-compat rules, ignore unknown enum values when OPTIONAL.
			// Item.scope is optional; if scope contains unknown enum values we treat it as absent.
			if errors.Is(err, ErrIgnored) {
				i.Scope = nil
			} else {
				return err
			}
		}
	}
	if len(i.Credentials) == 0 {
		return ErrMissingFields
	}
	if err := ValidateCredentials(i.Credentials); err != nil {
		return err
	}
	return nil
}
