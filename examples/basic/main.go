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
	// Construct a minimal note credential as raw JSON (type discrimination will be added elsewhere)
	noteCred := json.RawMessage(`{"type":"note","content":{"fieldType":"string","value":"hello world"}}`)

	now := uint64(time.Now().Unix())

	item := cxf.Item{
		ID:          "item-1",
		Title:       "Sample Item",
		Credentials: []json.RawMessage{noteCred},
		Tags:        []string{"example", "note"},
	}

	account := cxf.Account{
		ID:       "account-1",
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
