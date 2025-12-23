package cxf

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"testing"
)

func makeMinimalHeader() *Header {
	cred := json.RawMessage(`{"type":"totp","secret":"JBSWY3DPEHPK3PXP","algorithm":"SHA1","period":30,"digits":6}`)
	item := Item{
		ID:          "aXRlbS0x", // base64url("item-1")
		Title:       "Test Item",
		Credentials: []json.RawMessage{cred},
	}
	account := Account{
		ID:       "YWNjb3VudC0x", // base64url("account-1")
		Username: "user",
		Email:    "user@example.com",
		Items:    []Item{item},
	}
	return &Header{
		Version: Version{
			Major: VersionMajor,
			Minor: VersionMinor,
		},
		ExporterRpId:        "exporter.example.com",
		ExporterDisplayName: "Exporter",
		Timestamp:           1710000000,
		Accounts:            []Account{account},
	}
}

func TestNewHeader(t *testing.T) {
	h := NewHeader("exp.example", "Exporter", 1700000000)
	if h.Version.Major != VersionMajor || h.Version.Minor != VersionMinor {
		t.Fatalf("expected version %d.%d, got %d.%d", VersionMajor, VersionMinor, h.Version.Major, h.Version.Minor)
	}
	if h.ExporterRpId != "exp.example" || h.ExporterDisplayName != "Exporter" {
		t.Fatalf("exporter fields not set correctly: %+v", h)
	}
	if h.Timestamp != 1700000000 {
		t.Fatalf("timestamp not set")
	}
	if h.Accounts == nil {
		t.Fatalf("accounts slice should be initialized")
	}
}

func TestHeaderValidateValid(t *testing.T) {
	h := makeMinimalHeader()
	if err := h.Validate(); err != nil {
		t.Fatalf("expected valid header, got error: %v", err)
	}
}

func TestHeaderValidateMissingAccounts(t *testing.T) {
	h := NewHeader("exp.example", "Exporter", 1700000000)
	err := h.Validate()
	if err != ErrMissingAccount {
		t.Fatalf("expected ErrMissingAccount, got %v", err)
	}
}

func TestHeaderValidateMissingTimestamp(t *testing.T) {
	h := NewHeader("exp.example", "Exporter", 0)
	err := h.Validate()
	if err != ErrInvalidFormat {
		t.Fatalf("expected ErrInvalidFormat for zero timestamp, got %v", err)
	}
}

func TestAccountValidateMissingItems(t *testing.T) {
	acc := Account{
		ID:       "YWNjb3VudC0x",
		Username: "user",
		Email:    "user@example.com",
		Items:    []Item{},
	}
	err := acc.Validate()
	if err != ErrMissingItem {
		t.Fatalf("expected ErrMissingItem, got %v", err)
	}
}

func TestCollectionValidate(t *testing.T) {
	col := Collection{
		ID:    "",
		Title: "",
	}
	if err := col.Validate(); err != ErrMissingFields {
		t.Fatalf("expected ErrMissingFields, got %v", err)
	}
	col = Collection{ID: "Y29sMQ", Title: "Title"}
	if err := col.Validate(); err != nil {
		t.Fatalf("expected valid collection, got %v", err)
	}
}

func TestItemValidate(t *testing.T) {
	item := Item{
		ID:    "",
		Title: "",
	}
	if err := item.Validate(); err != ErrMissingFields {
		t.Fatalf("expected ErrMissingFields for missing ID/title, got %v", err)
	}
	item = Item{
		ID:    "aXRlbS0x",
		Title: "Item",
	}
	if err := item.Validate(); err != ErrMissingFields {
		t.Fatalf("expected ErrMissingFields for missing credentials, got %v", err)
	}
	item.Credentials = []json.RawMessage{json.RawMessage(`{"type":"totp","secret":"JBSWY3DPEHPK3PXP","algorithm":"SHA1","period":30,"digits":6}`)}
	if err := item.Validate(); err != nil {
		t.Fatalf("expected valid item, got %v", err)
	}
}

func TestHeaderJSONRoundTrip(t *testing.T) {
	h := makeMinimalHeader()
	data, err := h.Marshal()
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	var out Header
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if err := out.Validate(); err != nil {
		t.Fatalf("round-trip validation failed: %v", err)
	}
	if out.ExporterRpId != h.ExporterRpId || out.ExporterDisplayName != h.ExporterDisplayName {
		t.Fatalf("exporter fields mismatch after round trip")
	}
	if len(out.Accounts) != 1 || len(out.Accounts[0].Items) != 1 {
		t.Fatalf("accounts/items mismatch after round trip")
	}
}

func TestValidateEditableFieldBoolean(t *testing.T) {
	f := EditableField{FieldType: FieldTypeBoolean, Value: json.RawMessage("true")}
	if err := ValidateEditableField(f); err != nil {
		t.Fatalf("expected boolean field to be valid, got %v", err)
	}

	f.Value = json.RawMessage("\"notbool\"")
	if err := ValidateEditableField(f); err != ErrInvalidFieldValue {
		t.Fatalf("expected ErrInvalidFieldValue for non-boolean, got %v", err)
	}
}

func TestValidateEditableFieldNumber(t *testing.T) {
	f := EditableField{FieldType: FieldTypeNumber, Value: json.RawMessage("123.45")}
	if err := ValidateEditableField(f); err != nil {
		t.Fatalf("expected number field to be valid, got %v", err)
	}

	f.Value = json.RawMessage("\"string\"")
	if err := ValidateEditableField(f); err != ErrInvalidFieldValue {
		t.Fatalf("expected ErrInvalidFieldValue for non-numeric, got %v", err)
	}
}

func TestValidateEditableFieldInvalidType(t *testing.T) {
	f := EditableField{FieldType: "unknown-type", Value: json.RawMessage("true")}
	if err := ValidateEditableField(f); err != ErrInvalidFieldType {
		t.Fatalf("expected ErrInvalidFieldType, got %v", err)
	}
}

func TestValidateEditableFieldMissingValue(t *testing.T) {
	f := EditableField{FieldType: FieldTypeString, Value: json.RawMessage("")}
	if err := ValidateEditableField(f); err != ErrMissingFields {
		t.Fatalf("expected ErrMissingFields for empty value, got %v", err)
	}
}

func TestValidateEditableFieldInvalidID(t *testing.T) {
	f := EditableField{ID: "not-base64url", FieldType: FieldTypeString, Value: json.RawMessage("\"ok\"")}
	if err := ValidateEditableField(f); err == nil {
		t.Fatalf("expected error for invalid id")
	}
}

func TestValidateEditableFieldsStopsOnError(t *testing.T) {
	fields := []EditableField{
		{FieldType: FieldTypeBoolean, Value: json.RawMessage("false")},
		{FieldType: "bad-type", Value: json.RawMessage("true")},
		{FieldType: FieldTypeNumber, Value: json.RawMessage("10")},
	}
	if err := ValidateEditableFields(fields); err != ErrInvalidFieldType {
		t.Fatalf("expected ErrInvalidFieldType, got %v", err)
	}
}

func TestValidateEditableFieldStringTypes(t *testing.T) {
	f := EditableField{FieldType: FieldTypeString, Value: json.RawMessage("\"hello\"")}
	if err := ValidateEditableField(f); err != nil {
		t.Fatalf("expected string field to be valid, got %v", err)
	}

	f.Value = json.RawMessage("123") // not a JSON string, should fail
	if err := ValidateEditableField(f); err != ErrInvalidFieldValue {
		t.Fatalf("expected ErrInvalidFieldValue for non-string value, got %v", err)
	}
}

func TestValidateCredentialTOTPValid(t *testing.T) {
	raw := json.RawMessage(`{"type":"totp","secret":"JBSWY3DPEHPK3PXP","algorithm":"SHA1","period":30,"digits":6}`)
	if err := ValidateCredential(raw); err != nil {
		t.Fatalf("expected valid TOTP credential, got %v", err)
	}
}

func TestValidateCredentialTOTPInvalid(t *testing.T) {
	raw := json.RawMessage(`{"type":"totp","secret":"!!!","algorithm":"SHA1","period":30,"digits":6}`)
	if err := ValidateCredential(raw); err != ErrInvalidCredential {
		t.Fatalf("expected ErrInvalidCredential for invalid secret, got %v", err)
	}
}

func TestValidateCredentialPasskeyValid(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		t.Fatalf("failed to marshal pkcs8: %v", err)
	}
	priv := EncodeBase64URL(der)
	credID, err := GenerateIdentifier(16)
	if err != nil {
		t.Fatalf("failed to generate credential id: %v", err)
	}

	raw := json.RawMessage(fmt.Sprintf(`{"type":"passkey","credentialId":"%s","privateKey":"%s","signCount":0}`, credID, priv))
	if err := ValidateCredential(raw); err != nil {
		t.Fatalf("expected valid passkey credential, got %v", err)
	}
}

func TestValidateCredentialPasskeyInvalidSignCount(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		t.Fatalf("failed to marshal pkcs8: %v", err)
	}
	priv := EncodeBase64URL(der)
	credID, err := GenerateIdentifier(16)
	if err != nil {
		t.Fatalf("failed to generate credential id: %v", err)
	}

	raw := json.RawMessage(fmt.Sprintf(`{"type":"passkey","credentialId":"%s","privateKey":"%s","signCount":1}`, credID, priv))
	if err := ValidateCredential(raw); err != ErrInvalidCredential {
		t.Fatalf("expected ErrInvalidCredential for non-zero signCount, got %v", err)
	}
}

func TestValidateCredentialFileValid(t *testing.T) {
	data := []byte("hello")
	dataB64 := EncodeBase64URL(data)
	hash := sha256.Sum256(data)
	integrity := EncodeBase64URL(hash[:])
	raw := json.RawMessage(fmt.Sprintf(`{"type":"file","name":"hello.txt","mimeType":"text/plain","data":"%s","integrityHash":"%s"}`, dataB64, integrity))
	if err := ValidateCredential(raw); err != nil {
		t.Fatalf("expected valid file credential, got %v", err)
	}
}

func TestValidateCredentialFileInvalidHash(t *testing.T) {
	data := []byte("hello")
	dataB64 := EncodeBase64URL(data)
	raw := json.RawMessage(fmt.Sprintf(`{"type":"file","name":"hello.txt","mimeType":"text/plain","data":"%s","integrityHash":"bogus"}`, dataB64))
	if err := ValidateCredential(raw); err != ErrInvalidCredential {
		t.Fatalf("expected ErrInvalidCredential for bad hash, got %v", err)
	}
}

func TestComputeIntegrityHash(t *testing.T) {
	data := []byte("hello")
	sum := sha256.Sum256(data)
	want := EncodeBase64URL(sum[:])
	got := ComputeIntegrityHash(data)
	if got != want {
		t.Fatalf("ComputeIntegrityHash mismatch: got %s, want %s", got, want)
	}
}

func TestValidateIntegrityHash(t *testing.T) {
	data := []byte("hello")
	hash := ComputeIntegrityHash(data)

	if err := ValidateIntegrityHash(data, hash); err != nil {
		t.Fatalf("expected valid integrity hash, got %v", err)
	}

	if err := ValidateIntegrityHash(data, "bogus"); err != ErrInvalidCredential {
		t.Fatalf("expected ErrInvalidCredential for mismatched hash, got %v", err)
	}

	if err := ValidateIntegrityHash(data, ""); err != ErrMissingFields {
		t.Fatalf("expected ErrMissingFields for empty hash, got %v", err)
	}
}
