package cxf

import (
	"encoding/json"
	"testing"
)

func makeMinimalHeader() *Header {
	cred := json.RawMessage(`{"type":"note"}`)
	item := Item{
		ID:          "item-1",
		Title:       "Test Item",
		Credentials: []json.RawMessage{cred},
	}
	account := Account{
		ID:       "account-1",
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

func TestAccountValidateMissingItems(t *testing.T) {
	acc := Account{
		ID:       "acc-1",
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
	col = Collection{ID: "c1", Title: "Title"}
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
		ID:    "item-1",
		Title: "Item",
	}
	if err := item.Validate(); err != ErrMissingFields {
		t.Fatalf("expected ErrMissingFields for missing credentials, got %v", err)
	}
	item.Credentials = []json.RawMessage{json.RawMessage(`{"type":"note"}`)}
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
