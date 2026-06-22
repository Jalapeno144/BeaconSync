// Package main is the entry point for the BeaconSync client.
//
// The client loads its YAML configuration, wires together the
// transport layer and interactive CLI, then starts the REPL loop.
package main

import (
	"fmt"
	"os"

	"github.com/Jalapeno144/BeaconSync/internal/cli"
	"github.com/Jalapeno144/BeaconSync/internal/config"
)

func main() {
	res := config.Load("config.yaml")

	if res.Warning != nil {
		fmt.Printf("[!] CONFIG WARNING: %v — using defaults where needed.\n", res.Warning)
	} else {
		fmt.Println("[+] Configuration loaded from config.yaml")
	}

	app := cli.New(&res.Config)

	if err := app.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "[!] FATAL: %v\n", err)
		os.Exit(1)
	}
}
