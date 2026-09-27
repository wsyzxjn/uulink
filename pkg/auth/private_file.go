package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// SaveJSONFile atomically writes a private JSON document with owner-only
// permissions. It is intended for short-lived credentials and room/share
// state that must never be observed half-written by another process.
func SaveJSONFile(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal JSON: %w", err)
	}
	data = append(data, '\n')
	return writePrivateFile(path, ".uulink-json-*", data)
}

// writePrivateFile replaces path with data through a same-directory temporary
// file. Renaming within the directory makes readers observe either the old
// complete document or the new complete document, never a partial write.
func writePrivateFile(path, pattern string, data []byte) error {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return fmt.Errorf("create private temp file: %w", err)
	}
	tempName := temp.Name()
	defer os.Remove(tempName)

	if err := temp.Chmod(0600); err != nil {
		_ = temp.Close()
		return fmt.Errorf("set private file permissions: %w", err)
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return fmt.Errorf("write private temp file: %w", err)
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return fmt.Errorf("sync private temp file: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close private temp file: %w", err)
	}
	if err := os.Rename(tempName, path); err != nil {
		return fmt.Errorf("replace private file: %w", err)
	}
	return nil
}
