package cxf

import (
	"fmt"
	"io"

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

// MarshalHeaderCBOR serializes the CXF header to CBOR format.
func MarshalHeaderCBOR(h *Header) ([]byte, error) {
	return cborEncMode.Marshal(h)
}

// UnmarshalHeaderCBOR deserializes a CBOR byte array into a Header.
func UnmarshalHeaderCBOR(data []byte) (*Header, error) {
	var header Header
	if err := cborDecMode.Unmarshal(data, &header); err != nil {
		return nil, fmt.Errorf("failed to unmarshal CBOR: %w", err)
	}

	return &header, nil
}

// UnmarshalHeaderCBORSized deserializes CBOR into a Header while enforcing an input size limit.
// This is intended for use with untrusted inputs to mitigate memory/DoS risks.
func UnmarshalHeaderCBORSized(r io.Reader, maxBytes int64) (*Header, error) {
	var header Header
	if err := DecodeCBORSized(r, maxBytes, &header); err != nil {
		return nil, err
	}
	return &header, nil
}

// EncodeCBOR encodes arbitrary data to CBOR format.
func EncodeCBOR(v interface{}) ([]byte, error) {
	return cborEncMode.Marshal(v)
}

// DecodeCBOR decodes CBOR data into the provided value.
func DecodeCBOR(data []byte, v interface{}) error {
	return cborDecMode.Unmarshal(data, v)
}

// DecodeCBORSized decodes CBOR from an io.Reader, enforcing a hard input size limit and strict
// single-document framing (no trailing non-whitespace).
//
// This is intended for use with untrusted inputs.
func DecodeCBORSized(r io.Reader, maxBytes int64, v interface{}) error {
	if maxBytes <= 0 {
		return fmt.Errorf("maxBytes must be positive")
	}

	dec := cborDecMode.NewDecoder(io.LimitReader(r, maxBytes))
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("failed to decode CBOR: %w", err)
	}

	// Enforce "exactly one CBOR data item" semantics: after decoding v, the stream must be EOF.
	// (CBOR doesn't have whitespace, so any extra bytes are trailing data.)
	var extra interface{}
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("unexpected trailing data after CBOR item")
		}
		return fmt.Errorf("failed while checking trailing CBOR data: %w", err)
	}

	return nil
}
