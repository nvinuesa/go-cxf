package cxf

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

var (
	// cborEncMode is the CBOR encoding mode with proper time handling
	cborEncMode cbor.EncMode
	// cborDecMode is the CBOR decoding mode
	cborDecMode cbor.DecMode
)

func init() {
	// Create encoding mode with RFC3339 time format
	encOpts := cbor.EncOptions{
		Time:    cbor.TimeRFC3339,
		TimeTag: cbor.EncTagRequired,
	}

	var err error
	cborEncMode, err = encOpts.EncMode()
	if err != nil {
		panic(fmt.Sprintf("failed to create CBOR encoding mode: %v", err))
	}

	// Create decoding mode with RFC3339 time format
	decOpts := cbor.DecOptions{
		TimeTag: cbor.DecTagRequired,
	}

	cborDecMode, err = decOpts.DecMode()
	if err != nil {
		panic(fmt.Sprintf("failed to create CBOR decoding mode: %v", err))
	}
}

// MarshalContainerCBOR serializes the container to CBOR format.
func MarshalContainerCBOR(c *Container) ([]byte, error) {
	return cborEncMode.Marshal(c)
}

// UnmarshalContainerCBOR deserializes a CBOR byte array into a Container.
func UnmarshalContainerCBOR(data []byte) (*Container, error) {
	var container Container
	if err := cborDecMode.Unmarshal(data, &container); err != nil {
		return nil, fmt.Errorf("failed to unmarshal CBOR: %w", err)
	}

	return &container, nil
}

// MarshalCredentialCBOR serializes a credential to CBOR format.
func MarshalCredentialCBOR(c *Credential) ([]byte, error) {
	return cborEncMode.Marshal(c)
}

// UnmarshalCredentialCBOR deserializes a CBOR byte array into a Credential.
func UnmarshalCredentialCBOR(data []byte) (*Credential, error) {
	var credential Credential
	if err := cborDecMode.Unmarshal(data, &credential); err != nil {
		return nil, fmt.Errorf("failed to unmarshal CBOR: %w", err)
	}

	return &credential, nil
}

// EncodeCBOR encodes arbitrary data to CBOR format.
func EncodeCBOR(v interface{}) ([]byte, error) {
	return cborEncMode.Marshal(v)
}

// DecodeCBOR decodes CBOR data into the provided value.
func DecodeCBOR(data []byte, v interface{}) error {
	return cborDecMode.Unmarshal(data, v)
}
