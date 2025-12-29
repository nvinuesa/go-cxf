package cxf

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

// DecodeHeaderJSONStrict decodes a CXF Header from JSON with a hard size limit and requires
// that the input is exactly one JSON document (no trailing data).
//
// This is intended for use with untrusted input.
//
// Note: This does not (yet) enforce the "required array must be present even if empty" rule from
// the spec; it focuses on bounded decoding and basic structural correctness.
func DecodeHeaderJSONStrict(r io.Reader, maxBytes int64) (*Header, error) {
	if maxBytes <= 0 {
		return nil, fmt.Errorf("maxBytes must be positive")
	}

	dec := json.NewDecoder(io.LimitReader(r, maxBytes))
	dec.DisallowUnknownFields()

	var h Header
	if err := dec.Decode(&h); err != nil {
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
		return ErrInvalidFieldType
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
	// privateKey must be valid base64url
	if err := ValidateBase64URL(c.PrivateKey); err != nil {
		return ErrInvalidCredential
	}
	// Optional date fields
	for _, f := range []*EditableField{c.CreationDate, c.ExpiryDate} {
		if f != nil {
			if err := ValidateEditableFieldWithExpectedType(*f, FieldTypeDate); err != nil {
				return err
			}
		}
	}
	// Optional string field
	if c.KeyGenerationSource != nil {
		if err := ValidateEditableFieldWithExpectedType(*c.KeyGenerationSource, FieldTypeString); err != nil {
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
		return ErrInvalidCredential
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
	if _, err := DecodeBase64URL(c.UserHandle); err != nil {
		return ErrInvalidCredential
	}
	if _, err := DecodeBase64URL(c.Key); err != nil {
		return ErrInvalidCredential
	}
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
			decoded, err := DecodeBase64URL(v)
			if err != nil {
				return ErrInvalidCredential
			}
			if len(decoded) != 32 {
				return ErrInvalidCredential
			}
		}
	}

	if ext.CredBlob != "" {
		if err := ValidateBase64URL(ext.CredBlob); err != nil {
			return ErrInvalidCredential
		}
	}

	if ext.LargeBlob != nil {
		if ext.LargeBlob.UncompressedSize == 0 || ext.LargeBlob.Data == "" {
			return ErrMissingFields
		}
		if _, err := DecodeBase64URL(ext.LargeBlob.Data); err != nil {
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
	if err := ValidateBase64URL(c.IntegrityHash); err != nil {
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
		return ValidateBasicAuthCredential(c)
	case CredentialTypeAPIKey:
		var c APIKeyCredential
		if err := json.Unmarshal(raw, &c); err != nil {
			return ErrInvalidCredential
		}
		return ValidateAPIKeyCredential(c)
	case CredentialTypeAddress:
		var c AddressCredential
		if err := json.Unmarshal(raw, &c); err != nil {
			return ErrInvalidCredential
		}
		return ValidateAddressCredential(c)
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
		return ValidateIdentityDocumentCredential(c)
	case CredentialTypeDriversLicense:
		var c DriversLicenseCredential
		if err := json.Unmarshal(raw, &c); err != nil {
			return ErrInvalidCredential
		}
		return ValidateDriversLicenseCredential(c)
	case CredentialTypePassport:
		var c PassportCredential
		if err := json.Unmarshal(raw, &c); err != nil {
			return ErrInvalidCredential
		}
		return ValidatePassportCredential(c)
	case CredentialTypePersonName:
		var c PersonNameCredential
		if err := json.Unmarshal(raw, &c); err != nil {
			return ErrInvalidCredential
		}
		return ValidatePersonNameCredential(c)
	case CredentialTypeCustomFields:
		var c CustomFieldsCredential
		if err := json.Unmarshal(raw, &c); err != nil {
			return ErrInvalidCredential
		}
		return ValidateCustomFieldsCredential(c)
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
		return ValidateWiFiCredential(c)
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
		return ValidateTOTPCredential(c)
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
		return ValidateCreditCardCredential(c)
	case CredentialTypeNote:
		var c NoteCredential
		if err := json.Unmarshal(raw, &c); err != nil {
			return ErrInvalidCredential
		}
		return ValidateNoteCredential(c)
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

// Extension is a generic extension payload.
type Extension struct {
	Name string                 `json:"name"`
	Data map[string]interface{} `json:"data,omitempty"`
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
	if len(i.Credentials) == 0 {
		return ErrMissingFields
	}
	if err := ValidateCredentials(i.Credentials); err != nil {
		return err
	}
	return nil
}
