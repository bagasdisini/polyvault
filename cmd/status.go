package cmd

import "fmt"

func runStatus() error {
	fmt.Println("Vault Status")
	fmt.Println("============")
	fmt.Println("State: sealed")
	fmt.Println("Version: 1.0.0")
	fmt.Println("Storage: file")
	return nil
}
