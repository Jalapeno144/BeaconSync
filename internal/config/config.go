// Package config handles loading and managing the BeaconSync client
// configuration from YAML files.
package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Result struct {
	Config  Config
	Warning error
	Source  string // "file" | "default"
}

// Config holds the complete client configuration.
type Config struct {
	Transport   TransportConfig   `yaml:"transport"`
	HTTPOptions HTTPOptionsConfig `yaml:"http_options"`
}

// TransportConfig holds transport-related settings.
type TransportConfig struct {
	ServerAddr string `yaml:"server_addr"`
	Protocol   string `yaml:"protocol"`
	Timeout    int    `yaml:"timeout"`
}

// HTTPOptionsConfig holds fine-tuning parameters for the HTTP transport.
type HTTPOptionsConfig struct {
	MaxIdleConns      int  `yaml:"max_idle_conns"`
	IdleConnTimeout   int  `yaml:"idle_conn_timeout"`
	DisableKeepAlives bool `yaml:"disable_keep_alives"`
}

// DefaultConfig returns a Config populated with safe defaults suitable
// for local development.
func DefaultConfig() Config {
	return Config{
		Transport: TransportConfig{
			ServerAddr: "127.0.0.1:8080",
			Protocol:   "http",
			Timeout:    10,
		},
		HTTPOptions: HTTPOptionsConfig{
			MaxIdleConns:      10,
			IdleConnTimeout:   30,
			DisableKeepAlives: false,
		},
	}
}

// Load reads a YAML configuration file and returns the parsed Config.
// When the file cannot be read or parsed the returned Config is still
// valid (it holds the default values) and the error describes the
// problem. Callers can therefore treat a non-nil error as a warning.
func Load(path string) Result {
	cfg := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		return Result{
			Config:  cfg,
			Warning: err,
			Source:  "default",
		}
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Result{
			Config:  cfg,
			Warning: err,
			Source:  "default",
		}
	}

	return Result{
		Config:  cfg,
		Warning: nil,
		Source:  "file",
	}
}
