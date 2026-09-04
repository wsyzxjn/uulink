package auth

import (
	"encoding/json"
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
		Hostname: "hostname",
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
		loaded.DeviceID != cfg.DeviceID || loaded.UserID != cfg.UserID || loaded.Hostname != cfg.Hostname {
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

func TestEffectiveHostnameUsesConfiguredValue(t *testing.T) {
	cfg := &Config{Hostname: "custom-host"}

	hostname, err := cfg.EffectiveHostname()
	if err != nil {
		t.Fatalf("EffectiveHostname() error: %v", err)
	}
	if hostname != "custom-host" {
		t.Fatalf("EffectiveHostname() = %q, want custom-host", hostname)
	}
}

func TestEffectiveHostnameFallsBackToSystemHostname(t *testing.T) {
	cfg := &Config{}

	got, err := cfg.EffectiveHostname()
	if err != nil {
		t.Fatalf("EffectiveHostname() error: %v", err)
	}
	want, err := os.Hostname()
	if err != nil {
		t.Fatalf("os.Hostname() error: %v", err)
	}
	if got != want {
		t.Fatalf("EffectiveHostname() = %q, want %q", got, want)
	}
}

func TestUnmarshalPortMappingFormats(t *testing.T) {
	jsonBlob := `[
		{"local_port": 8080, "remote_port": 8080},
		{"local_port": "9000-9005", "remote_port": "8000-8005"},
		{"range": "7000-7002:6000-6002"}
	]`

	var mappings []PortMapping
	if err := json.Unmarshal([]byte(jsonBlob), &mappings); err != nil {
		t.Fatalf("unmarshal port mappings: %v", err)
	}

	if len(mappings) != 3 {
		t.Fatalf("len(mappings) = %d, want 3", len(mappings))
	}
	if mappings[0].LocalPort != 8080 || mappings[0].RemotePort != 8080 {
		t.Errorf("mapping[0] = %+v", mappings[0])
	}
	if mappings[1].LocalRange != "9000-9005" || mappings[1].RemoteRange != "8000-8005" {
		t.Errorf("mapping[1] = %+v", mappings[1])
	}
	if mappings[2].Range != "7000-7002:6000-6002" {
		t.Errorf("mapping[2] = %+v", mappings[2])
	}
}

func TestEnsureClientID(t *testing.T) {
	cfg := &Config{}
	if !cfg.EnsureClientID() {
		t.Fatal("EnsureClientID should return true when ClientID was empty")
	}
	if cfg.ClientID == "" {
		t.Fatal("ClientID is still empty after EnsureClientID")
	}
	original := cfg.ClientID
	if cfg.EnsureClientID() {
		t.Fatal("EnsureClientID should return false when ClientID was already set")
	}
	if cfg.ClientID != original {
		t.Fatalf("ClientID changed from %s to %s", original, cfg.ClientID)
	}
}

func TestLoadOrInitConfigFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "new-config.json")

	// 1. File does not exist: creates default config with persistent ClientID
	cfg, err := LoadOrInitConfigFile(path)
	if err != nil {
		t.Fatalf("LoadOrInitConfigFile: %v", err)
	}
	if cfg.ClientID == "" {
		t.Fatal("generated config has empty ClientID")
	}
	origID := cfg.ClientID

	// 2. File now exists: reloading gives the exact same ClientID
	reloaded, err := LoadOrInitConfigFile(path)
	if err != nil {
		t.Fatalf("reload LoadOrInitConfigFile: %v", err)
	}
	if reloaded.ClientID != origID {
		t.Fatalf("reloaded ClientID = %s, want %s", reloaded.ClientID, origID)
	}
}
