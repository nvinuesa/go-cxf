package cxf

import (
	"crypto/sha256"
	"encoding/json"
	"testing"
)

func minimalTOTP() json.RawMessage {
	return json.RawMessage(`{"type":"totp","secret":"JBSWY3DPEHPK3PXP","algorithm":"sha1","period":30,"digits":6}`)
}

func makeMinimalHeader() *Header {
	cred := minimalTOTP()
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
	item.Credentials = []json.RawMessage{minimalTOTP()}
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

	f.Value = json.RawMessage("123")
	if err := ValidateEditableField(f); err != ErrInvalidFieldValue {
		t.Fatalf("expected ErrInvalidFieldValue for non-string value, got %v", err)
	}
}

func TestValidateCredentialTOTPValid(t *testing.T) {
	raw := minimalTOTP()
	if err := ValidateCredential(raw); err != nil {
		t.Fatalf("expected valid TOTP credential, got %v", err)
	}
}

func TestValidateCredentialTOTPInvalid(t *testing.T) {
	raw := json.RawMessage(`{"type":"totp","secret":"!!!","algorithm":"sha1","period":30,"digits":6}`)
	if err := ValidateCredential(raw); err != ErrInvalidCredential {
		t.Fatalf("expected ErrInvalidCredential for invalid secret, got %v", err)
	}
}

func TestValidateCredentialPasskeyValid(t *testing.T) {
	credID, err := GenerateIdentifier(16)
	if err != nil {
		t.Fatalf("failed to generate credential id: %v", err)
	}
	userHandle := EncodeBase64URL([]byte("user"))
	key := EncodeBase64URL([]byte("pkcs8-key"))
	raw := json.RawMessage(`{"type":"passkey","credentialId":"` + credID + `","key":"` + key + `","rpId":"example.com","username":"user","userDisplayName":"User","userHandle":"` + userHandle + `"}`)
	if err := ValidateCredential(raw); err != nil {
		t.Fatalf("expected valid passkey credential, got %v", err)
	}
}

func TestValidateCredentialPasskeyInvalidHmacLength(t *testing.T) {
	credID, _ := GenerateIdentifier(8)
	userHandle := EncodeBase64URL([]byte("user"))
	key := EncodeBase64URL([]byte("key"))
	short := EncodeBase64URL([]byte("short-bytes"))
	raw := json.RawMessage(`{
		"type":"passkey",
		"credentialId":"` + credID + `",
		"key":"` + key + `",
		"rpId":"example.com",
		"username":"user",
		"userDisplayName":"User",
		"userHandle":"` + userHandle + `",
		"fido2Extensions":{
			"hmacCredentials":{
				"algorithm":"HS256",
				"credWithUV":"` + short + `",
				"credWithoutUV":"` + short + `"
			}
		}
	}`)
	if err := ValidateCredential(raw); err != ErrInvalidCredential {
		t.Fatalf("expected ErrInvalidCredential for short hmac secrets, got %v", err)
	}
}

func TestValidateCredentialFileValid(t *testing.T) {
	integrity := EncodeBase64URL([]byte("hash"))
	raw := json.RawMessage(`{"type":"file","id":"ZmlsZWlk","name":"hello.txt","decryptedSize":5,"integrityHash":"` + integrity + `"}`)
	if err := ValidateCredential(raw); err != nil {
		t.Fatalf("expected valid file credential, got %v", err)
	}
}

func TestValidateCredentialFileMissingFields(t *testing.T) {
	raw := json.RawMessage(`{"type":"file","id":"","name":"hello.txt","decryptedSize":0,"integrityHash":""}`)
	if err := ValidateCredential(raw); err != ErrMissingFields {
		t.Fatalf("expected ErrMissingFields for incomplete file, got %v", err)
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

func TestValidateCredentialBasicAuthValid(t *testing.T) {
	raw := json.RawMessage(`{"type":"basic-auth","username":{"fieldType":"string","value":"\"user\""},"password":{"fieldType":"concealed-string","value":"\"pass\""}}`)
	if err := ValidateCredential(raw); err != nil {
		t.Fatalf("expected valid basic-auth credential, got %v", err)
	}
}

func TestValidateCredentialBasicAuthMissingFields(t *testing.T) {
	raw := json.RawMessage(`{"type":"basic-auth"}`)
	if err := ValidateCredential(raw); err != ErrMissingFields {
		t.Fatalf("expected ErrMissingFields for missing username/password, got %v", err)
	}
}

func TestValidateCredentialCreditCardValid(t *testing.T) {
	raw := json.RawMessage(`{"type":"credit-card","number":{"fieldType":"concealed-string","value":"\"4111 1111 1111 1111\""},"expiryDate":{"fieldType":"year-month","value":"\"2025-12\""}}`)
	if err := ValidateCredential(raw); err != nil {
		t.Fatalf("expected valid credit-card credential, got %v", err)
	}
}

func TestValidateCredentialCreditCardMissingAll(t *testing.T) {
	raw := json.RawMessage(`{"type":"credit-card"}`)
	if err := ValidateCredential(raw); err != ErrMissingFields {
		t.Fatalf("expected ErrMissingFields for empty credit-card, got %v", err)
	}
}

func TestValidateCredentialNoteMissingContent(t *testing.T) {
	raw := json.RawMessage(`{"type":"note"}`)
	if err := ValidateCredential(raw); err != ErrMissingFields {
		t.Fatalf("expected ErrMissingFields for empty note, got %v", err)
	}
}

func TestValidateCredentialNoteValid(t *testing.T) {
	raw := json.RawMessage(`{"type":"note","content":{"fieldType":"string","value":"\"hello\""}}`)
	if err := ValidateCredential(raw); err != nil {
		t.Fatalf("expected valid note, got %v", err)
	}
}

func TestValidateCredentialAPIKeyValid(t *testing.T) {
	raw := json.RawMessage(`{"type":"api-key","key":{"fieldType":"concealed-string","value":"\"secret-key\""},"validFrom":{"fieldType":"date","value":"\"2025-03-13\""}}`)
	if err := ValidateCredential(raw); err != nil {
		t.Fatalf("expected valid api-key credential, got %v", err)
	}
}

func TestValidateCredentialAPIKeyMissingAll(t *testing.T) {
	raw := json.RawMessage(`{"type":"api-key"}`)
	if err := ValidateCredential(raw); err != ErrMissingFields {
		t.Fatalf("expected ErrMissingFields for empty api-key, got %v", err)
	}
}

func TestValidateCredentialAddressValid(t *testing.T) {
	raw := json.RawMessage(`{
		"type":"address",
		"streetAddress":{"fieldType":"string","value":"\"123 Main St\""},
		"country":{"fieldType":"country-code","value":"\"US\""}
	}`)
	if err := ValidateCredential(raw); err != nil {
		t.Fatalf("expected valid address credential, got %v", err)
	}
}

func TestValidateCredentialAddressMissingAll(t *testing.T) {
	raw := json.RawMessage(`{"type":"address"}`)
	if err := ValidateCredential(raw); err != ErrMissingFields {
		t.Fatalf("expected ErrMissingFields for empty address, got %v", err)
	}
}

func TestValidateCredentialGeneratedPasswordValid(t *testing.T) {
	raw := json.RawMessage(`{"type":"generated-password","password":"p@ssw0rd!"}`)
	if err := ValidateCredential(raw); err != nil {
		t.Fatalf("expected valid generated-password credential, got %v", err)
	}
}

func TestValidateCredentialGeneratedPasswordMissingPassword(t *testing.T) {
	raw := json.RawMessage(`{"type":"generated-password","password":""}`)
	if err := ValidateCredential(raw); err != ErrMissingFields {
		t.Fatalf("expected ErrMissingFields for missing password, got %v", err)
	}
}

func TestValidateCredentialPersonName(t *testing.T) {
	raw := json.RawMessage(`{"type":"person-name","fullName":{"fieldType":"string","value":"\"Ada Lovelace\""}}`)
	if err := ValidateCredential(raw); err != nil {
		t.Fatalf("expected valid person-name credential, got %v", err)
	}

	rawMissing := json.RawMessage(`{"type":"person-name"}`)
	if err := ValidateCredential(rawMissing); err != ErrMissingFields {
		t.Fatalf("expected ErrMissingFields for person-name with no fields, got %v", err)
	}
}

func TestValidateCredentialIdentityDocument(t *testing.T) {
	raw := json.RawMessage(`{
		"type":"identity-document",
		"documentNumber":{"fieldType":"string","value":"\"ID123\""},
		"issueDate":{"fieldType":"date","value":"\"2024-01-01\""},
		"issuingCountry":{"fieldType":"country-code","value":"\"US\""}
	}`)
	if err := ValidateCredential(raw); err != nil {
		t.Fatalf("expected valid identity-document credential, got %v", err)
	}

	rawMissing := json.RawMessage(`{"type":"identity-document"}`)
	if err := ValidateCredential(rawMissing); err != ErrMissingFields {
		t.Fatalf("expected ErrMissingFields for empty identity-document, got %v", err)
	}
}

func TestValidateCredentialDriversLicense(t *testing.T) {
	raw := json.RawMessage(`{
		"type":"drivers-license",
		"documentNumber":{"fieldType":"string","value":"\"DL123\""},
		"expiryDate":{"fieldType":"date","value":"\"2026-05-05\""},
		"issuingCountry":{"fieldType":"country-code","value":"\"CA\""}
	}`)
	if err := ValidateCredential(raw); err != nil {
		t.Fatalf("expected valid drivers-license, got %v", err)
	}

	rawMissing := json.RawMessage(`{"type":"drivers-license"}`)
	if err := ValidateCredential(rawMissing); err != ErrMissingFields {
		t.Fatalf("expected ErrMissingFields for empty drivers-license, got %v", err)
	}
}

func TestValidateCredentialPassport(t *testing.T) {
	raw := json.RawMessage(`{
		"type":"passport",
		"documentNumber":{"fieldType":"string","value":"\"P123\""},
		"validFrom":{"fieldType":"date","value":"\"2023-01-01\""},
		"issuingCountry":{"fieldType":"country-code","value":"\"GB\""}
	}`)
	if err := ValidateCredential(raw); err != nil {
		t.Fatalf("expected valid passport, got %v", err)
	}

	rawMissing := json.RawMessage(`{"type":"passport"}`)
	if err := ValidateCredential(rawMissing); err != ErrMissingFields {
		t.Fatalf("expected ErrMissingFields for empty passport, got %v", err)
	}
}

func TestValidateCredentialCustomFields(t *testing.T) {
	raw := json.RawMessage(`{
		"type":"custom-fields",
		"fields":[{"fieldType":"string","value":"\"foo\""}]
	}`)
	if err := ValidateCredential(raw); err != nil {
		t.Fatalf("expected valid custom-fields, got %v", err)
	}

	rawMissing := json.RawMessage(`{"type":"custom-fields","fields":[]}`)
	if err := ValidateCredential(rawMissing); err != ErrMissingFields {
		t.Fatalf("expected ErrMissingFields for empty fields, got %v", err)
	}
}

func TestValidateCredentialSSHKey(t *testing.T) {
	raw := json.RawMessage(`{
		"type":"ssh-key",
		"privateKey":{"fieldType":"concealed-string","value":"\"PRIVATE\""},
		"keyType":{"fieldType":"string","value":"\"ed25519\""}
	}`)
	if err := ValidateCredential(raw); err != nil {
		t.Fatalf("expected valid ssh-key, got %v", err)
	}

	rawMissing := json.RawMessage(`{"type":"ssh-key","keyType":{"fieldType":"string","value":"\"ed25519\""}}`)
	if err := ValidateCredential(rawMissing); err != ErrMissingFields {
		t.Fatalf("expected ErrMissingFields for ssh-key without keys, got %v", err)
	}
}

func TestValidateCredentialWiFi(t *testing.T) {
	raw := json.RawMessage(`{
		"type":"wifi",
		"ssid":{"fieldType":"string","value":"\"MyWiFi\""},
		"security":{"fieldType":"wifi-network-security-type","value":"\"wpa2\""},
		"password":{"fieldType":"concealed-string","value":"\"secret\""},
		"hidden":{"fieldType":"boolean","value":false}
	}`)
	if err := ValidateCredential(raw); err != nil {
		t.Fatalf("expected valid wifi, got %v", err)
	}

	rawMissing := json.RawMessage(`{"type":"wifi"}`)
	if err := ValidateCredential(rawMissing); err != ErrMissingFields {
		t.Fatalf("expected ErrMissingFields for wifi without ssid, got %v", err)
	}
}

func TestValidateCredentialItemReference(t *testing.T) {
	raw := json.RawMessage(`{"type":"item-reference","itemId":"aXRlbS0x","accountId":"YWNjb3VudC0x"}`)
	if err := ValidateCredential(raw); err != nil {
		t.Fatalf("expected valid item-reference, got %v", err)
	}

	rawInvalid := json.RawMessage(`{"type":"item-reference","itemId":"not_base64!"}`)
	if err := ValidateCredential(rawInvalid); err == nil {
		t.Fatalf("expected error for invalid item-reference id")
	}
}
