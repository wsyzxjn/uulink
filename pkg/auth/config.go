package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/google/uuid"
)

// EffectiveHostname returns the configured hostname, or the current system
// hostname when the config leaves it unset.
func (c *Config) EffectiveHostname() (string, error) {
	if c.Hostname != "" {
		return c.Hostname, nil
	}
	hostname, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("read system hostname: %w", err)
	}
	if hostname == "" {
		return "", fmt.Errorf("system hostname is empty")
	}
	return hostname, nil
}

// SaveConfigFile atomically writes cfg as JSON with owner-only permissions.
func SaveConfigFile(path string, cfg *Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	data = append(data, '\n')

	return writePrivateFile(path, ".uulink-config-*", data)
}

// LoadOrInitConfigFile loads the config at path. When the file does not exist
// it creates one with a random, persistent client_id so an accountless client
// keeps a stable identity across restarts.
func LoadOrInitConfigFile(path string) (*Config, error) {
	cfg, err := LoadConfigFile(path)
	switch {
	case err == nil:
		if cfg.ClientID != "" {
			return cfg, nil
		}
	case errors.Is(err, os.ErrNotExist):
		cfg = &Config{}
	default:
		return nil, err
	}

	id, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("generate client id: %w", err)
	}
	cfg.ClientID = id.String()
	if err := SaveConfigFile(path, cfg); err != nil {
		return nil, fmt.Errorf("initialize config: %w", err)
	}
	return cfg, nil
}
