package cmd

import (
	"fmt"
	"net/http"
	"os"
	"time"
)

var (
	serverAddr = "http://localhost:8200"
	httpClient = &http.Client{Timeout: 10 * time.Second}
)

func runPut() error {
	if len(os.Args) < 4 {
		return fmt.Errorf("usage: ironvault put <key> <value>")
	}

	key := os.Args[2]
	value := os.Args[3]

	fmt.Printf("Storing secret '%s'...\n", key)
	// TODO: Actually store the secret
	_ = value

	fmt.Println("Secret stored successfully!")
	return nil
}

func runGet() error {
	if len(os.Args) < 3 {
		return fmt.Errorf("usage: ironvault get <key>")
	}

	key := os.Args[2]

	fmt.Printf("Retrieving secret '%s'...\n", key)
	// TODO: Actually retrieve the secret

	fmt.Println("secret-value-here")
	return nil
}

func runDelete() error {
	if len(os.Args) < 3 {
		return fmt.Errorf("usage: ironvault delete <key>")
	}

	key := os.Args[2]

	fmt.Printf("Deleting secret '%s'...\n", key)
	// TODO: Actually delete the secret

	fmt.Println("Secret deleted successfully!")
	return nil
}

func runList() error {
	fmt.Println("Secrets:")
	fmt.Println("========")
	// TODO: Actually list secrets
	fmt.Println("  - db-password")
	fmt.Println("  - api-key")
	fmt.Println("  - tls-cert")
	return nil
}
