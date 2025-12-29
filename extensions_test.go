package cxf

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestDecodeSharedExtensionNotSharedIsIgnored(t *testing.T) {
	ext := Extension{
		Name: "not-shared",
		Data: json.RawMessage(`{"accessors":[]}`),
	}
	if _, err := DecodeSharedExtension(ext); !errors.Is(err, ErrIgnored) {
		t.Fatalf("expected ErrIgnored for non-shared extension name, got %v", err)
	}
}

func TestDecodeSharedExtensionMissingDataIsInvalid(t *testing.T) {
	ext := Extension{
		Name: "shared",
		Data: nil,
	}
	if _, err := DecodeSharedExtension(ext); err == nil {
		t.Fatalf("expected error for missing data, got nil")
	}
}

func TestDecodeSharedExtensionNullDataIsInvalid(t *testing.T) {
	ext := Extension{
		Name: "shared",
		Data: json.RawMessage(`null`),
	}
	if _, err := DecodeSharedExtension(ext); err == nil {
		t.Fatalf("expected error for null data, got nil")
	}
}

func TestDecodeSharedExtensionValidEmptyAccessorsOK(t *testing.T) {
	ext := Extension{
		Name: "shared",
		Data: json.RawMessage(`{"accessors":[]}`),
	}
	got, err := DecodeSharedExtension(ext)
	if err != nil {
		t.Fatalf("expected decode to succeed, got %v", err)
	}
	if got == nil {
		t.Fatalf("expected non-nil decoded shared extension")
	}
	if got.Accessors == nil {
		t.Fatalf("expected accessors to be present (possibly empty), got nil")
	}
	if len(got.Accessors) != 0 {
		t.Fatalf("expected 0 accessors, got %d", len(got.Accessors))
	}
}

func TestDecodeSharedExtensionMissingAccessorsIsError(t *testing.T) {
	ext := Extension{
		Name: "shared",
		Data: json.RawMessage(`{}`),
	}
	if _, err := DecodeSharedExtension(ext); err == nil {
		t.Fatalf("expected error for missing required member accessors, got nil")
	}
}

func TestDecodeSharedExtensionAccessorMissingPermissionsIsError(t *testing.T) {
	ext := Extension{
		Name: "shared",
		Data: json.RawMessage(`{"accessors":[{"type":"user","accountId":"abc","name":"User"}]}`),
	}
	if _, err := DecodeSharedExtension(ext); err == nil {
		t.Fatalf("expected error for missing required member permissions, got nil")
	}
}

func TestDecodeSharedExtensionAccessorUnknownTypeIsIgnored(t *testing.T) {
	ext := Extension{
		Name: "shared",
		Data: json.RawMessage(`{"accessors":[{"type":"new-type","accountId":"id","name":"name","permissions":["read"]}]}`),
	}
	if _, err := DecodeSharedExtension(ext); !errors.Is(err, ErrIgnored) {
		t.Fatalf("expected ErrIgnored for unknown accessor type, got %v", err)
	}
}

func TestDecodeSharedExtensionAccessorUnknownPermissionIsIgnored(t *testing.T) {
	ext := Extension{
		Name: "shared",
		Data: json.RawMessage(`{"accessors":[{"type":"user","accountId":"id","name":"name","permissions":["read","admin"]}]}`),
	}
	if _, err := DecodeSharedExtension(ext); !errors.Is(err, ErrIgnored) {
		t.Fatalf("expected ErrIgnored for unknown permission, got %v", err)
	}
}

func TestValidateSharingAccessorMissingTypeIsError(t *testing.T) {
	a := SharingAccessor{
		Type:        "",
		AccountID:   "id",
		Name:        "name",
		Permissions: []SharingAccessorPermission{SharingAccessorPermissionRead},
	}
	if err := ValidateSharingAccessor(a); err == nil {
		t.Fatalf("expected error for missing type, got nil")
	}
}

func TestValidateSharingAccessorPermissionsPresentEmptyOK(t *testing.T) {
	a := SharingAccessor{
		Type:        SharingAccessorTypeUser,
		AccountID:   "id",
		Name:        "name",
		Permissions: []SharingAccessorPermission{},
	}
	if err := ValidateSharingAccessor(a); err != nil {
		t.Fatalf("expected empty permissions slice to be allowed (present but empty), got %v", err)
	}
}

func TestValidateSharedExtensionAccessorsPresentEmptyOK(t *testing.T) {
	s := SharedExtension{
		Accessors: []SharingAccessor{},
	}
	if err := ValidateSharedExtension(s); err != nil {
		t.Fatalf("expected empty accessors slice to be allowed (present but empty), got %v", err)
	}
}

func TestValidateSharingAccessorMissingAccountIDIsError(t *testing.T) {
	a := SharingAccessor{
		Type:        SharingAccessorTypeUser,
		Name:        "name",
		Permissions: []SharingAccessorPermission{SharingAccessorPermissionRead},
	}
	if err := ValidateSharingAccessor(a); err == nil {
		t.Fatalf("expected error for missing accountId, got nil")
	}
}

func TestValidateSharingAccessorMissingNameIsError(t *testing.T) {
	a := SharingAccessor{
		Type:        SharingAccessorTypeUser,
		AccountID:   "id",
		Permissions: []SharingAccessorPermission{SharingAccessorPermissionRead},
	}
	if err := ValidateSharingAccessor(a); err == nil {
		t.Fatalf("expected error for missing name, got nil")
	}
}
