package main

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/nvinuesa/go-cxf"
)

func main() {
	fmt.Println("=== CXF Header/Account/Item Example ===")
	header := buildExampleHeader()
	printJSON(header)

	fmt.Println("\n=== Validate ===")
	if err := header.Validate(); err != nil {
		log.Fatalf("validation failed: %v", err)
	}
	fmt.Println("validation OK")
}

func buildExampleHeader() *cxf.Header {
	// Construct a minimal TOTP credential as raw JSON
	totpCred := json.RawMessage(`{\"type\":\"totp\",\"secret\":\"JBSWY3DPEHPK3PXP\",\"algorithm\":\"SHA1\",\"period\":30,\"digits\":6}`)

	now := uint64(time.Now().Unix())

	item := cxf.Item{
		ID:          "aXRlbS0x", // base64url("item-1")
		Title:       "Sample Item",
		Credentials: []json.RawMessage{totpCred},
		Tags:        []string{"example", "totp"},
	}

	account := cxf.Account{
		ID:       "YWNjb3VudC0x", // base64url("account-1")
		Username: "user",
		Email:    "user@example.com",
		Items:    []cxf.Item{item},
	}

	header := cxf.NewHeader("exporter.example.com", "Exporter App", now)
	header.Accounts = append(header.Accounts, account)
	return header
}

func printJSON(h *cxf.Header) {
	data, err := h.MarshalIndent()
	if err != nil {
		log.Fatalf("marshal error: %v", err)
	}
	fmt.Println(string(data))
}
