package auth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSaveConfigFileIsAtomicAndOwnerOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	cfg := &Config{
		JWT:      "token",
		ClientID: "client",
		DeviceID: "device",
		UserID:   "user",
		Mappings: []PortMapping{{
			LocalHost:  "127.0.0.1",
			LocalPort:  18080,
			RemoteHost: "127.0.0.1",
			RemotePort: 8080,
		}},
	}

	if err := SaveConfigFile(path, cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	loaded, err := LoadConfigFile(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if loaded.JWT != cfg.JWT || loaded.ClientID != cfg.ClientID ||
		loaded.DeviceID != cfg.DeviceID || loaded.UserID != cfg.UserID {
		t.Fatalf("loaded config mismatch: %+v", loaded)
	}
	if len(loaded.Mappings) != 1 || loaded.Mappings[0] != cfg.Mappings[0] {
		t.Fatalf("loaded mappings mismatch: %+v", loaded.Mappings)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat config: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("config permissions = %o, want 600", info.Mode().Perm())
	}

	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("read config dir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("config directory has %d entries, want only config.json", len(entries))
	}
}
