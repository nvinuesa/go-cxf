package main

import (
	"fmt"
	"log"
	"time"

	"github.com/nvinuesa/go-cxf"
)

func main() {
	// Example 1: Create a basic CXF container with a credential
	fmt.Println("=== Example 1: Basic CXF Container ===")
	basicExample()

	fmt.Println("\n=== Example 2: Complete Credential with Attestation ===")
	completeExample()

	fmt.Println("\n=== Example 3: Multiple Credentials ===")
	multipleCredentialsExample()

	fmt.Println("\n=== Example 4: JSON and CBOR Serialization ===")
	serializationExample()
}

func basicExample() {
	// Create a new CXF container
	container := cxf.NewContainer("credential")

	// Generate credential and user IDs
	credID, err := cxf.GenerateCredentialID(32)
	if err != nil {
		log.Fatalf("Failed to generate credential ID: %v", err)
	}

	userID, err := cxf.GenerateUserID(32)
	if err != nil {
		log.Fatalf("Failed to generate user ID: %v", err)
	}

	// Create a new credential
	cred := cxf.NewCredential(
		credID,
		cxf.CredentialTypePasskey,
		"example.com",
		"Example Website",
		userID,
		"user@example.com",
		"Example User",
	)

	// Add public key information
	cred.PublicKey = &cxf.PublicKeyCredential{
		CredentialID: credID,
		Algorithm:    -7, // ES256 (ECDSA with SHA-256)
		PublicKey:    cxf.EncodeBase64URL([]byte("example-public-key-data")),
		SignCount:    0,
		Transports:   []cxf.AuthenticatorTransport{cxf.TransportInternal},
	}

	// Add credential to container
	container.AddCredential(*cred)

	// Marshal to JSON
	jsonData, err := container.MarshalIndent()
	if err != nil {
		log.Fatalf("Failed to marshal container: %v", err)
	}

	fmt.Printf("Container JSON:\n%s\n", string(jsonData))
}

func completeExample() {
	container := cxf.NewContainer("credential")

	credID, _ := cxf.GenerateCredentialID(32)
	userID, _ := cxf.GenerateUserID(32)

	cred := cxf.NewCredential(
		credID,
		cxf.CredentialTypeFIDO2,
		"secure-app.example.com",
		"Secure Application",
		userID,
		"admin@example.com",
		"Admin User",
	)

	// Set last used timestamp
	lastUsed := time.Now().UTC()
	cred.LastUsed = &lastUsed

	// Add public key
	cred.PublicKey = &cxf.PublicKeyCredential{
		CredentialID: credID,
		Algorithm:    -7,
		PublicKey:    cxf.EncodeBase64URL([]byte("public-key-bytes")),
		SignCount:    42,
		Transports:   []cxf.AuthenticatorTransport{cxf.TransportUSB, cxf.TransportNFC},
		AAGUID:       "00000000-0000-0000-0000-000000000000",
	}

	// Add attestation data
	cred.Attestation = &cxf.AttestationData{
		Format: cxf.AttestationFormatPacked,
		Statement: map[string]interface{}{
			"alg": -7,
			"sig": cxf.EncodeBase64URL([]byte("signature-bytes")),
		},
		ClientDataJSON:    cxf.EncodeBase64URL([]byte("client-data-json")),
		AuthenticatorData: cxf.EncodeBase64URL([]byte("authenticator-data")),
	}

	// Add custom metadata
	cred.Metadata = map[string]interface{}{
		"device":   "Secure Key",
		"location": "US",
	}

	container.AddCredential(*cred)

	// Validate the container
	if err := container.Validate(); err != nil {
		log.Fatalf("Container validation failed: %v", err)
	}

	jsonData, _ := container.MarshalIndent()
	fmt.Printf("Complete Credential:\n%s\n", string(jsonData))
}

func multipleCredentialsExample() {
	container := cxf.NewContainer("credential-set")

	// Add multiple credentials for the same relying party
	for i := 0; i < 3; i++ {
		credID, _ := cxf.GenerateCredentialID(32)
		userID, _ := cxf.GenerateUserID(16)

		cred := cxf.NewCredential(
			credID,
			cxf.CredentialTypePublicKey,
			"multi-device.example.com",
			"Multi-Device App",
			userID,
			fmt.Sprintf("user%d@example.com", i+1),
			fmt.Sprintf("User %d", i+1),
		)

		cred.PublicKey = &cxf.PublicKeyCredential{
			CredentialID: credID,
			Algorithm:    -7,
			PublicKey:    cxf.EncodeBase64URL([]byte(fmt.Sprintf("key-%d", i))),
			SignCount:    uint32(i * 10),
			Transports:   []cxf.AuthenticatorTransport{cxf.TransportUSB},
		}

		container.AddCredential(*cred)
	}

	fmt.Printf("Container with %d credentials created\n", len(container.Credentials))
	fmt.Printf("Total credentials: %d\n", len(container.Credentials))
}

func serializationExample() {
	container := cxf.NewContainer("credential")

	credID, _ := cxf.GenerateCredentialID(32)
	userID, _ := cxf.GenerateUserID(32)

	cred := cxf.NewCredential(
		credID,
		cxf.CredentialTypePasskey,
		"example.org",
		"Example Organization",
		userID,
		"test@example.org",
		"Test User",
	)

	cred.PublicKey = &cxf.PublicKeyCredential{
		CredentialID: credID,
		Algorithm:    -7,
		PublicKey:    cxf.EncodeBase64URL([]byte("test-public-key")),
		SignCount:    0,
	}

	container.AddCredential(*cred)

	// JSON Serialization
	jsonData, err := container.Marshal()
	if err != nil {
		log.Fatalf("JSON marshal failed: %v", err)
	}
	fmt.Printf("JSON size: %d bytes\n", len(jsonData))

	// CBOR Serialization
	cborData, err := cxf.MarshalContainerCBOR(container)
	if err != nil {
		log.Fatalf("CBOR marshal failed: %v", err)
	}
	fmt.Printf("CBOR size: %d bytes\n", len(cborData))

	// Compare sizes
	savings := float64(len(jsonData)-len(cborData)) / float64(len(jsonData)) * 100
	fmt.Printf("CBOR is %.2f%% smaller than JSON\n", savings)

	// Deserialize from JSON
	restoredFromJSON, err := cxf.Unmarshal(jsonData)
	if err != nil {
		log.Fatalf("JSON unmarshal failed: %v", err)
	}

	// Deserialize from CBOR
	restoredFromCBOR, err := cxf.UnmarshalContainerCBOR(cborData)
	if err != nil {
		log.Fatalf("CBOR unmarshal failed: %v", err)
	}

	fmt.Printf("\nDeserialization successful!")
	fmt.Printf("\nJSON version: %s, credentials: %d", restoredFromJSON.Version, len(restoredFromJSON.Credentials))
	fmt.Printf("\nCBOR version: %s, credentials: %d\n", restoredFromCBOR.Version, len(restoredFromCBOR.Credentials))
}
