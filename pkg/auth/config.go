package auth

import (
	"encoding/json"
	"fmt"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

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

	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, ".uulink-config-*")
	if err != nil {
		return fmt.Errorf("create config temp file: %w", err)
	}
	tempName := temp.Name()
	defer os.Remove(tempName)

	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return fmt.Errorf("write config temp file: %w", err)
	}
	if err := temp.Chmod(0600); err != nil {
		temp.Close()
		return fmt.Errorf("set config permissions: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close config temp file: %w", err)
	}
	if err := os.Rename(tempName, path); err != nil {
		return fmt.Errorf("replace config: %w", err)
	}
	return nil
}

// EnsureClientID ensures the config has a valid ClientID, generating a random
// UUID if none is set. Returns whether the config was modified.
func (c *Config) EnsureClientID() bool {
	if c.ClientID != "" {
		return false
	}
	id, err := uuid.NewRandom()
	if err != nil {
		c.ClientID = fmt.Sprintf("%016X", time.Now().UnixNano())
		return true
	}
	c.ClientID = strings.ToUpper(id.String())
	return true
}

// NewDefaultConfig initializes a new Config with a randomly generated,
// fixed ClientID.
func NewDefaultConfig() *Config {
	cfg := &Config{}
	cfg.EnsureClientID()
	return cfg
}

// LoadOrInitConfigFile loads config from path, or generates a default config
// with a persistent random client_id if the file does not exist.
func LoadOrInitConfigFile(path string) (*Config, error) {
	cfg, err := LoadConfigFile(path)
	if err == nil {
		if cfg.EnsureClientID() {
			_ = SaveConfigFile(path, cfg)
		}
		return cfg, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		cfg = NewDefaultConfig()
		if err := SaveConfigFile(path, cfg); err != nil {
			// If saving fails (e.g. read-only dir), still return the generated in-memory config
			return cfg, nil
		}
		return cfg, nil
	}
	return nil, err
}
