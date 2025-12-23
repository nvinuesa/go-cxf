package cxf

import (
	"encoding/json"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func makeMinimalHeaderCBOR() *Header {
	cred := json.RawMessage(`{"type":"totp","secret":"JBSWY3DPEHPK3PXP","algorithm":"sha1","period":30,"digits":6}`)
	item := Item{
		ID:          "aXRlbS0x", // base64url("item-1")
		Title:       "Item",
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

func TestHeaderMarshalCBOR(t *testing.T) {
	h := makeMinimalHeaderCBOR()
	data, err := MarshalHeaderCBOR(h)
	if err != nil {
		t.Fatalf("MarshalHeaderCBOR() error = %v", err)
	}
	if len(data) == 0 {
		t.Fatalf("expected non-empty CBOR data")
	}

	// Verify it's valid CBOR by decoding generically.
	var generic map[string]interface{}
	if err := cbor.Unmarshal(data, &generic); err != nil {
		t.Fatalf("Marshaled data is not valid CBOR: %v", err)
	}
}

func TestUnmarshalHeaderCBOR(t *testing.T) {
	orig := makeMinimalHeaderCBOR()

	data, err := MarshalHeaderCBOR(orig)
	if err != nil {
		t.Fatalf("MarshalHeaderCBOR() error = %v", err)
	}

	restored, err := UnmarshalHeaderCBOR(data)
	if err != nil {
		t.Fatalf("UnmarshalHeaderCBOR() error = %v", err)
	}

	if err := restored.Validate(); err != nil {
		t.Fatalf("restored header validation failed: %v", err)
	}

	if restored.ExporterRpId != orig.ExporterRpId || restored.ExporterDisplayName != orig.ExporterDisplayName {
		t.Fatalf("exporter fields mismatch after round trip")
	}
	if len(restored.Accounts) != 1 || len(restored.Accounts[0].Items) != 1 {
		t.Fatalf("accounts/items mismatch after round trip")
	}
}

func TestHeaderMarshalCBORWithWiFiAndSSHRoundTrip(t *testing.T) {
	wifi := json.RawMessage(`{"type":"wifi","ssid":{"fieldType":"string","value":"MyWiFi"},"networkSecurityType":{"fieldType":"wifi-network-security-type","value":"wpa2-personal"},"passphrase":{"fieldType":"concealed-string","value":"secret"},"hidden":{"fieldType":"boolean","value":false}}`)
	ssh := json.RawMessage(`{"type":"ssh-key","keyType":"ssh-ed25519","privateKey":"` + EncodeBase64URL([]byte("PRIVATE-KEY-DATA")) + `","keyComment":"work"}`)

	item := Item{
		ID:          "aXRlbS0y",
		Title:       "WiFi+SSH",
		Credentials: []json.RawMessage{wifi, ssh},
	}
	account := Account{
		ID:       "YWNjb3VudC0y",
		Username: "user2",
		Email:    "user2@example.com",
		Items:    []Item{item},
	}
	h := &Header{
		Version: Version{
			Major: VersionMajor,
			Minor: VersionMinor,
		},
		ExporterRpId:        "exporter.example.com",
		ExporterDisplayName: "Exporter",
		Timestamp:           1710000001,
		Accounts:            []Account{account},
	}

	data, err := MarshalHeaderCBOR(h)
	if err != nil {
		t.Fatalf("MarshalHeaderCBOR() error = %v", err)
	}

	restored, err := UnmarshalHeaderCBOR(data)
	if err != nil {
		t.Fatalf("UnmarshalHeaderCBOR() error = %v", err)
	}

	if err := restored.Validate(); err != nil {
		t.Fatalf("restored header validation failed: %v", err)
	}

	if len(restored.Accounts) != 1 || len(restored.Accounts[0].Items) != 1 {
		t.Fatalf("accounts/items mismatch after round trip")
	}
	if len(restored.Accounts[0].Items[0].Credentials) != 2 {
		t.Fatalf("expected two credentials after round trip")
	}
}

func TestUnmarshalHeaderCBORInvalid(t *testing.T) {
	invalid := []byte{0xff, 0xff, 0xff}
	if _, err := UnmarshalHeaderCBOR(invalid); err == nil {
		t.Fatalf("expected error for invalid CBOR, got nil")
	}
}

func TestEncodeDecodeCBOR(t *testing.T) {
	original := map[string]interface{}{
		"key1": "value1",
		"key2": int64(42),
		"key3": true,
	}

	data, err := EncodeCBOR(original)
	if err != nil {
		t.Fatalf("EncodeCBOR() error = %v", err)
	}

	var decoded map[string]interface{}
	if err := DecodeCBOR(data, &decoded); err != nil {
		t.Fatalf("DecodeCBOR() error = %v", err)
	}

	if decoded["key1"] != original["key1"] {
		t.Fatalf("key1 mismatch: %v != %v", decoded["key1"], original["key1"])
	}

	// key2 may decode as uint64 or int64 depending on encoder; normalize.
	switch v := decoded["key2"].(type) {
	case uint64:
		if int64(v) != original["key2"] {
			t.Fatalf("key2 mismatch: %v != %v", v, original["key2"])
		}
	case int64:
		if v != original["key2"] {
			t.Fatalf("key2 mismatch: %v != %v", v, original["key2"])
		}
	default:
		t.Fatalf("key2 decoded type unexpected: %T", decoded["key2"])
	}

	if decoded["key3"] != original["key3"] {
		t.Fatalf("key3 mismatch: %v != %v", decoded["key3"], original["key3"])
	}
}
