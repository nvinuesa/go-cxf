package cxf

import (
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
	ErrInvalidVersion  = errors.New("invalid CXF version")
	ErrInvalidFormat   = errors.New("invalid CXF format")
	ErrMissingAccount  = errors.New("missing account")
	ErrMissingItem     = errors.New("missing item")
	ErrMissingFields   = errors.New("missing required fields")
	ErrInvalidIDLength = errors.New("identifier exceeds 64 bytes")
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
	ID         string      `json:"id,omitempty"`
	FieldType  string      `json:"fieldType"`
	Value      string      `json:"value"`
	Label      string      `json:"label,omitempty"`
	Extensions []Extension `json:"extensions,omitempty"`
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
	if h.ExporterRpId == "" || h.ExporterDisplayName == "" {
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
	return nil
}

// Validate checks item invariants.
func (i *Item) Validate() error {
	if i.ID == "" || i.Title == "" {
		return ErrMissingFields
	}
	if len(i.Credentials) == 0 {
		return ErrMissingFields
	}
	return nil
}
