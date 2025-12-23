package cxf

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
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

	switch f.FieldType {
	case FieldTypeBoolean:
		var v bool
		if err := json.Unmarshal(f.Value, &v); err != nil {
			return ErrInvalidFieldValue
		}
	case FieldTypeNumber:
		dec := json.NewDecoder(bytes.NewReader(f.Value))
		dec.UseNumber()
		var v interface{}
		if err := dec.Decode(&v); err != nil {
			return ErrInvalidFieldValue
		}
		switch n := v.(type) {
		case json.Number:
			if _, err := n.Float64(); err != nil {
				return ErrInvalidFieldValue
			}
		default:
			return ErrInvalidFieldValue
		}
	default:
		var s string
		if err := json.Unmarshal(f.Value, &s); err != nil {
			return ErrInvalidFieldValue
		}
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

// BasicAuth credential schema.
type BasicAuthCredential struct {
	Type     string        `json:"type"`
	Urls     []string      `json:"urls"`
	Username EditableField `json:"username,omitempty"`
	Password EditableField `json:"password,omitempty"`
}

// TOTP credential schema.
type TOTPCredential struct {
	Type        string `json:"type"`
	Secret      string `json:"secret"`
	Algorithm   string `json:"algorithm"`
	Period      int    `json:"period"`
	Digits      int    `json:"digits"`
	Issuer      string `json:"issuer,omitempty"`
	AccountName string `json:"accountName,omitempty"`
}

var totpAllowedAlgorithms = map[string]struct{}{
	"SHA1":   {},
	"SHA256": {},
	"SHA512": {},
}

var totpAllowedDigits = map[int]struct{}{
	6: {}, 7: {}, 8: {},
}

// Passkey credential schema.
type PasskeyCredential struct {
	Type            string           `json:"type"`
	CredentialID    string           `json:"credentialId"`
	PrivateKey      string           `json:"privateKey,omitempty"`
	Key             json.RawMessage  `json:"key,omitempty"`
	RpId            string           `json:"rpId,omitempty"`
	UserName        string           `json:"userName,omitempty"`
	UserDisplayName string           `json:"userDisplayName,omitempty"`
	UserHandle      string           `json:"userHandle,omitempty"`
	PublicKey       string           `json:"publicKey,omitempty"`
	SignCount       uint32           `json:"signCount,omitempty"`
	Fido2Extensions *Fido2Extensions `json:"fido2Extensions,omitempty"`
}

type Fido2Extensions struct {
	HmacSecret       *Fido2HmacSecret       `json:"hmacSecret,omitempty"`
	CredBlob         string                 `json:"credBlob,omitempty"`
	LargeBlob        *Fido2LargeBlob        `json:"largeBlob,omitempty"`
	Payments         *bool                  `json:"payments,omitempty"`
	SupplementalKeys *Fido2SupplementalKeys `json:"supplementalKeys,omitempty"`
}

type Fido2HmacSecret struct {
	Algorithm string `json:"algorithm"`
	Secret    string `json:"secret"`
}

type Fido2LargeBlob struct {
	Size uint64 `json:"size"`
	Alg  string `json:"alg"`
	Data string `json:"data"`
}

type Fido2SupplementalKeys struct {
	Device   *bool `json:"device,omitempty"`
	Provider *bool `json:"provider,omitempty"`
}

// File credential schema.
type FileCredential struct {
	Type          string `json:"type"`
	Name          string `json:"name"`
	MimeType      string `json:"mimeType"`
	Data          string `json:"data"`
	IntegrityHash string `json:"integrityHash"`
}

// Credit card credential schema.
type CreditCardCredential struct {
	Type               string `json:"type"`
	Number             string `json:"number"`
	FullName           string `json:"fullName"`
	CardType           string `json:"cardType,omitempty"`
	VerificationNumber string `json:"verificationNumber,omitempty"`
	ExpiryDate         string `json:"expiryDate,omitempty"`
	ValidFrom          string `json:"validFrom,omitempty"`
}

// Note credential schema.
type NoteCredential struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

func ValidateBasicAuthCredential(c BasicAuthCredential) error {
	if c.Type != CredentialTypeBasicAuth {
		return ErrInvalidCredentialType
	}
	if len(c.Urls) == 0 {
		return ErrMissingFields
	}
	for _, u := range c.Urls {
		if u == "" {
			return ErrInvalidCredential
		}
	}
	if c.Username.FieldType == "" || len(c.Username.Value) == 0 {
		return ErrMissingFields
	}
	if err := ValidateEditableField(c.Username); err != nil {
		return err
	}
	if c.Password.FieldType == "" || len(c.Password.Value) == 0 {
		return ErrMissingFields
	}
	if err := ValidateEditableField(c.Password); err != nil {
		return err
	}
	return nil
}

func ValidateAPIKeyCredential(c APIKeyCredential) error {
	if c.Type != CredentialTypeAPIKey {
		return ErrInvalidCredentialType
	}
	fields := []*EditableField{c.Key, c.Username, c.KeyType, c.URL, c.ValidFrom, c.ExpiryDate}
	present := false
	for _, f := range fields {
		if f != nil {
			present = true
			if err := ValidateEditableField(*f); err != nil {
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
	for _, f := range fields {
		if f != nil {
			present = true
			if err := ValidateEditableField(*f); err != nil {
				return err
			}
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
	if c.CredentialID == "" {
		return ErrMissingFields
	}
	if err := ValidateIdentifier(c.CredentialID); err != nil {
		return err
	}

	hasPrivate := c.PrivateKey != ""
	hasKey := len(c.Key) > 0

	if !hasPrivate && !hasKey {
		return ErrMissingFields
	}

	if hasPrivate {
		privDER, err := DecodeBase64URL(c.PrivateKey)
		if err != nil {
			return ErrInvalidCredential
		}
		if _, err := x509.ParsePKCS8PrivateKey(privDER); err != nil {
			return ErrInvalidCredential
		}
	}

	if hasKey {
		var v interface{}
		if err := json.Unmarshal(c.Key, &v); err != nil {
			return ErrInvalidCredential
		}
		switch val := v.(type) {
		case string:
			if val == "" {
				return ErrInvalidCredential
			}
			if _, err := DecodeBase64URL(val); err != nil {
				return ErrInvalidCredential
			}
		case map[string]interface{}:
			if len(val) == 0 {
				return ErrInvalidCredential
			}
		default:
			return ErrInvalidCredential
		}
	}

	if c.PublicKey != "" {
		if _, err := DecodeBase64URL(c.PublicKey); err != nil {
			return ErrInvalidCredential
		}
	}

	extendedProvided := hasKey || c.RpId != "" || c.UserName != "" || c.UserDisplayName != "" || c.UserHandle != "" || c.Fido2Extensions != nil
	if extendedProvided {
		if c.RpId == "" || c.UserName == "" || c.UserDisplayName == "" || c.UserHandle == "" || !hasKey {
			return ErrMissingFields
		}
		if c.Fido2Extensions != nil {
			if err := validateFido2Extensions(c.Fido2Extensions); err != nil {
				return err
			}
		}
	}

	return nil
}

func validateFido2Extensions(ext *Fido2Extensions) error {
	if ext == nil {
		return nil
	}

	if ext.HmacSecret != nil {
		if ext.HmacSecret.Algorithm == "" || ext.HmacSecret.Secret == "" {
			return ErrMissingFields
		}
		if err := ValidateBase64URL(ext.HmacSecret.Secret); err != nil {
			return ErrInvalidCredential
		}
	}

	if ext.CredBlob != "" {
		if err := ValidateBase64URL(ext.CredBlob); err != nil {
			return ErrInvalidCredential
		}
	}

	if ext.LargeBlob != nil {
		if ext.LargeBlob.Size == 0 || ext.LargeBlob.Alg == "" || ext.LargeBlob.Data == "" {
			return ErrMissingFields
		}
		decoded, err := DecodeBase64URL(ext.LargeBlob.Data)
		if err != nil {
			return ErrInvalidCredential
		}
		if uint64(len(decoded)) != ext.LargeBlob.Size {
			return ErrInvalidCredential
		}
	}

	return nil
}

func ValidateFileCredential(c FileCredential) error {
	if c.Type != CredentialTypeFile {
		return ErrInvalidCredentialType
	}
	if c.Name == "" || c.MimeType == "" || c.Data == "" || c.IntegrityHash == "" {
		return ErrMissingFields
	}
	dataBytes, err := DecodeBase64URL(c.Data)
	if err != nil {
		return ErrInvalidCredential
	}
	expected := ComputeIntegrityHash(dataBytes)
	if expected != c.IntegrityHash {
		return ErrInvalidCredential
	}
	return nil
}

func ValidateCreditCardCredential(c CreditCardCredential) error {
	if c.Type != CredentialTypeCreditCard {
		return ErrInvalidCredentialType
	}
	normalized := normalizeCreditCardNumber(c.Number)
	if normalized == "" || c.FullName == "" {
		return ErrMissingFields
	}
	if len(normalized) < 12 || len(normalized) > 19 {
		return ErrInvalidCredential
	}
	if !luhnCheck(normalized) {
		return ErrInvalidCredential
	}
	return nil
}

func ValidateNoteCredential(c NoteCredential) error {
	if c.Type != CredentialTypeNote {
		return ErrInvalidCredentialType
	}
	if c.Text == "" {
		return ErrMissingFields
	}
	return nil
}

func normalizeCreditCardNumber(number string) string {
	buf := make([]byte, 0, len(number))
	for i := 0; i < len(number); i++ {
		ch := number[i]
		if ch == ' ' || ch == '-' {
			continue
		}
		buf = append(buf, ch)
	}
	return string(buf)
}

func luhnCheck(number string) bool {
	if number == "" {
		return false
	}
	sum := 0
	double := false
	for i := len(number) - 1; i >= 0; i-- {
		d := number[i]
		if d < '0' || d > '9' {
			return false
		}
		n := int(d - '0')
		if double {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		double = !double
	}
	return sum%10 == 0
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
		return ErrInvalidCredentialType
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
