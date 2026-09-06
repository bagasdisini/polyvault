package cmd

import (
	"fmt"
	"os"
)

// Execute runs the root command.
func Execute() error {
	if len(os.Args) < 2 {
		return printUsage()
	}

	switch os.Args[1] {
	case "server":
		return runServer()
	case "init":
		return runInit()
	case "unseal":
		return runUnseal()
	case "status":
		return runStatus()
	case "put":
		return runPut()
	case "get":
		return runGet()
	case "delete":
		return runDelete()
	case "list":
		return runList()
	case "help", "--help", "-h":
		return printUsage()
	default:
		return fmt.Errorf("unknown command: %s", os.Args[1])
	}
}

func printUsage() error {
	fmt.Println(`IronVault - A self-hosted secrets manager

Usage:
  ironvault <command> [arguments]

Commands:
  server    Start the vault server
  init      Initialize a new vault
  unseal    Unseal the vault with shares
  status    Show vault status
  put       Store a secret
  get       Retrieve a secret
  delete    Delete a secret
  list      List all secrets
  help      Show this help

Run 'ironvault <command> --help' for more information on a command.`)
	return nil
}
