package main

import (
	"encoding/json"
	"os"
)

// AllowlistConfig represents the allowlist configuration
type AllowlistConfig struct {
	AllowedIPs []string `json:"allowed_ips"`
}

// LoadAllowlistConfig loads the allowlist configuration from a JSON file
func LoadAllowlistConfig(path string) (*AllowlistConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg AllowlistConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
