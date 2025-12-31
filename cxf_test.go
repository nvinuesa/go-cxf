package cxf

import (
	"encoding/json"
	"testing"
)

func TestCredentialTypeConstants(t *testing.T) {
	// Verify credential type constants match expected kebab-case values
	tests := map[string]string{
		CredentialTypeAddress:           "address",
		CredentialTypeAPIKey:            "api-key",
		CredentialTypeBasicAuth:         "basic-auth",
		CredentialTypeCreditCard:        "credit-card",
		CredentialTypeCustomFields:      "custom-fields",
		CredentialTypeDriversLicense:    "drivers-license",
		CredentialTypeFile:              "file",
		CredentialTypeGeneratedPassword: "generated-password",
		CredentialTypeIdentityDocument:  "identity-document",
		CredentialTypeItemReference:     "item-reference",
		CredentialTypeNote:              "note",
		CredentialTypePasskey:           "passkey",
		CredentialTypePassport:          "passport",
		CredentialTypePersonName:        "person-name",
		CredentialTypeSSHKey:            "ssh-key",
		CredentialTypeTOTP:              "totp",
		CredentialTypeWiFi:              "wifi",
	}

	for got, want := range tests {
		if got != want {
			t.Errorf("credential type mismatch: got %q want %q", got, want)
		}
	}
}

func TestFieldTypeConstants(t *testing.T) {
	// Verify field type constants match expected kebab-case values
	tests := map[string]string{
		FieldTypeString:              "string",
		FieldTypeConcealedString:     "concealed-string",
		FieldTypeEmail:               "email",
		FieldTypeNumber:              "number",
		FieldTypeBoolean:             "boolean",
		FieldTypeDate:                "date",
		FieldTypeYearMonth:           "year-month",
		FieldTypeWifiNetworkSecurity: "wifi-network-security-type",
		FieldTypeCountryCode:         "country-code",
		FieldTypeSubdivisionCode:     "subdivision-code",
	}

	for got, want := range tests {
		if got != want {
			t.Errorf("field type mismatch: got %q want %q", got, want)
		}
	}
}

func TestVersionConstants(t *testing.T) {
	if VersionMajor != 1 {
		t.Errorf("expected VersionMajor 1, got %d", VersionMajor)
	}
	if VersionMinor != 0 {
		t.Errorf("expected VersionMinor 0, got %d", VersionMinor)
	}
}

func TestCredentialSerialization(t *testing.T) {
	// Test that credential types can be marshaled and unmarshaled correctly
	creds := []any{
		&BasicAuthCredential{
			Type:     CredentialTypeBasicAuth,
			Username: &EditableField{FieldType: FieldTypeString, Value: json.RawMessage(`"testuser"`)},
			Password: &EditableField{FieldType: FieldTypeConcealedString, Value: json.RawMessage(`"secret"`)},
		},
		&TOTPCredential{
			Type:      CredentialTypeTOTP,
			Secret:    "JBSWY3DPEHPK3PXP",
			Algorithm: "sha1",
			Period:    30,
			Digits:    6,
		},
		&PasskeyCredential{
			Type:            CredentialTypePasskey,
			CredentialID:    "Y3JlZGVudGlhbC0x",
			RpId:            "example.com",
			Username:        "user",
			UserDisplayName: "Test User",
			UserHandle:      "dXNlci0x",
			Key:             "a2V5LWRhdGE",
		},
		&FileCredential{
			Type:          CredentialTypeFile,
			ID:            "ZmlsZS0x",
			Name:          "test.txt",
			DecryptedSize: 1024,
			IntegrityHash: "dGVzdC1oYXNo", // placeholder hash
		},
		&GeneratedPasswordCredential{
			Type:     CredentialTypeGeneratedPassword,
			Password: "generated-password-123",
		},
		&NoteCredential{
			Type:    CredentialTypeNote,
			Content: &EditableField{FieldType: FieldTypeString, Value: json.RawMessage(`"Note content"`)},
		},
	}

	for _, cred := range creds {
		data, err := json.Marshal(cred)
		if err != nil {
			t.Fatalf("failed to marshal credential: %v", err)
		}

		// Verify type field is present
		var env struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(data, &env); err != nil {
			t.Fatalf("failed to unmarshal type: %v", err)
		}
		if env.Type == "" {
			t.Fatalf("credential type field is empty")
		}
	}
}

func TestWifiSecurityConstants(t *testing.T) {
	tests := map[string]string{
		WifiSecurityUnsecured:    "unsecured",
		WifiSecurityWPAPersonal:  "wpa-personal",
		WifiSecurityWPA2Personal: "wpa2-personal",
		WifiSecurityWPA3Personal: "wpa3-personal",
		WifiSecurityWEP:          "wep",
	}

	for got, want := range tests {
		if got != want {
			t.Errorf("wifi security type mismatch: got %q want %q", got, want)
		}
	}
}

func TestOTPHashAlgorithmConstants(t *testing.T) {
	tests := map[string]string{
		OTPHashAlgorithmSha1:   "sha1",
		OTPHashAlgorithmSha256: "sha256",
		OTPHashAlgorithmSha512: "sha512",
	}

	for got, want := range tests {
		if got != want {
			t.Errorf("OTP hash algorithm mismatch: got %q want %q", got, want)
		}
	}
}

func TestSharingAccessorTypeConstants(t *testing.T) {
	if SharingAccessorTypeUser != "user" {
		t.Errorf("expected SharingAccessorTypeUser = 'user', got %q", SharingAccessorTypeUser)
	}
	if SharingAccessorTypeGroup != "group" {
		t.Errorf("expected SharingAccessorTypeGroup = 'group', got %q", SharingAccessorTypeGroup)
	}
}

func TestSharingAccessorPermissionConstants(t *testing.T) {
	tests := map[SharingAccessorPermission]string{
		SharingAccessorPermissionRead:       "read",
		SharingAccessorPermissionReadSecret: "readSecret",
		SharingAccessorPermissionUpdate:     "update",
		SharingAccessorPermissionCreate:     "create",
		SharingAccessorPermissionDelete:     "delete",
		SharingAccessorPermissionShare:      "share",
		SharingAccessorPermissionManage:     "manage",
	}

	for got, want := range tests {
		if string(got) != want {
			t.Errorf("permission mismatch: got %q want %q", got, want)
		}
	}
}

func TestAndroidAppHashAlgorithmConstants(t *testing.T) {
	if AndroidAppHashAlgorithmSha256 != "sha256" {
		t.Errorf("expected AndroidAppHashAlgorithmSha256 = 'sha256', got %q", AndroidAppHashAlgorithmSha256)
	}
	if AndroidAppHashAlgorithmSha1 != "sha1" {
		t.Errorf("expected AndroidAppHashAlgorithmSha1 = 'sha1', got %q", AndroidAppHashAlgorithmSha1)
	}
}

func TestFido2HmacCredentialAlgorithmConstants(t *testing.T) {
	if Fido2HmacCredentialAlgorithmHmacSha256 != "hmac-sha256" {
		t.Errorf("expected 'hmac-sha256', got %q", Fido2HmacCredentialAlgorithmHmacSha256)
	}
}

func TestLinkedItemSerialization(t *testing.T) {
	li := LinkedItem{
		Item:    "aXRlbS0x",
		Account: "YWNjb3VudC0x",
	}

	data, err := json.Marshal(li)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var decoded LinkedItem
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if decoded.Item != li.Item || decoded.Account != li.Account {
		t.Fatalf("linked item mismatch")
	}
}

func TestCredentialScopeSerialization(t *testing.T) {
	scope := CredentialScope{
		Urls: []string{"https://example.com", "https://test.com"},
		AndroidApps: []AndroidAppIdCredential{
			{
				BundleId: "com.example.app",
				Name:     "Example App",
			},
		},
	}

	data, err := json.Marshal(scope)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var decoded CredentialScope
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if len(decoded.Urls) != len(scope.Urls) {
		t.Fatalf("urls count mismatch")
	}
	if len(decoded.AndroidApps) != len(scope.AndroidApps) {
		t.Fatalf("android apps count mismatch")
	}
}

func TestExtensionSerialization(t *testing.T) {
	ext := Extension{
		Name: "custom-extension",
		Data: json.RawMessage(`{"key":"value"}`),
	}

	data, err := json.Marshal(ext)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var decoded Extension
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if decoded.Name != ext.Name {
		t.Fatalf("name mismatch")
	}
}

func TestCollectionSerialization(t *testing.T) {
	creationAt := uint64(1700000000)
	coll := Collection{
		ID:         "Y29sLTE",
		CreationAt: &creationAt,
		Title:      "My Collection",
		Subtitle:   "A test collection",
		Items:      []LinkedItem{{Item: "aXRlbS0x"}},
	}

	data, err := json.Marshal(coll)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var decoded Collection
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if decoded.ID != coll.ID || decoded.Title != coll.Title {
		t.Fatalf("collection mismatch")
	}
}

func TestEditableFieldSerialization(t *testing.T) {
	ef := EditableField{
		ID:        "ZmllbGQtMQ",
		FieldType: FieldTypeString,
		Value:     json.RawMessage(`"test value"`),
		Label:     "Test Field",
	}

	data, err := json.Marshal(ef)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var decoded EditableField
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if decoded.FieldType != ef.FieldType || decoded.Label != ef.Label {
		t.Fatalf("editable field mismatch")
	}
}

func TestFido2ExtensionsSerialization(t *testing.T) {
	payments := true
	ext := Fido2Extensions{
		HmacCredentials: &Fido2HmacCredentials{
			Algorithm:     Fido2HmacCredentialAlgorithmHmacSha256,
			CredWithUV:    "Y3JlZFdpdGhVVg",
			CredWithoutUV: "Y3JlZFdpdGhvdXRVVg",
		},
		CredBlob: "Y3JlZEJsb2I",
		LargeBlob: &Fido2LargeBlob{
			UncompressedSize: 1024,
			Data:             "bGFyZ2VCbG9iRGF0YQ",
		},
		Payments: &payments,
	}

	data, err := json.Marshal(ext)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var decoded Fido2Extensions
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if decoded.HmacCredentials == nil || decoded.LargeBlob == nil {
		t.Fatalf("fido2 extensions fields not decoded")
	}
}
