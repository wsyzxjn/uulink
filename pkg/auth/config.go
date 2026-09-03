package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
