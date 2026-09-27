package auth

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestIdentityOverridesAreConsistent(t *testing.T) {
	t.Setenv("UULINK_CLIENT_VN", "")
	t.Setenv("UULINK_CLIENT_VC", "")
	t.Setenv("UULINK_STREAMER_VERSION", "")
	for _, platform := range []int{WindowsPlatform, MacPlatform} {
		cfg := &Config{Platform: platform, VersionName: "5.1.0", VersionCode: "20000", StreamerVersion: "V6.0.0"}
		i := cfg.Identity()
		h := BuildHeaders(cfg, "1")
		if h["X-Param-VN"] != i.VersionName || h["X-Param-VC"] != i.VersionCode || !strings.Contains(h["User-Agent"], "UURemote/5.1.0") || !strings.Contains(h["User-Agent"], "build:20000") || i.StreamerVersion != "V6.0.0" {
			t.Fatalf("inconsistent identity: %+v", h)
		}
	}
	t.Setenv("UULINK_CLIENT_VN", "5.2.0")
	t.Setenv("UULINK_CLIENT_VC", "20001")
	t.Setenv("UULINK_STREAMER_VERSION", "V6.1.0")
	cfg := &Config{VersionName: "5.1.0", StreamerVersion: "V6.0.0"}
	h := BuildHeaders(cfg, "1")
	if h["X-Param-VN"] != "5.2.0" || !strings.Contains(h["User-Agent"], "5.2.0") || cfg.Identity().StreamerVersion != "V6.1.0" {
		t.Fatal("environment override was not applied consistently")
	}
}

func TestProfileRoundTripAndRegistrationOverrides(t *testing.T) {
	var cfg Config
	err := json.Unmarshal([]byte(`{"version_name":"5.0.0","version_code":"10000","streamer_version":"V5.0.0","api_base_url":"https://example.com","client_profile":{"country":"JP","channel":"test","signing_key":"test-key"},"devices":{"mac":{"cpu":"Virtual CPU","memory":"8192","video":["Virtual GPU"]}},"network":{"stun_servers":[],"session_limit":24}}`), &cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var again Config
	if err := json.Unmarshal(data, &again); err != nil {
		t.Fatal(err)
	}
	if len(again.Network.STUNServers) != 0 || again.Network.STUNServers == nil || again.Network.SessionLimit != 24 || again.Identity().Country != "JP" {
		t.Fatalf("lost settings: %s", data)
	}
	body := again.Devices.RegistrationMetadata(MacPlatform)
	if body["cpu"] != "Virtual CPU" || body["memory"] != "8192" {
		t.Fatalf("lost device profile: %+v", body)
	}
	if _, present := body["client_id"]; present {
		t.Fatal("profile generated an identity")
	}
	h := BuildHeaders(&again, "1")
	if SignWithKey(again.Identity().SigningKey, "GET", "/test", h, "") == Sign("GET", "/test", h, "") {
		t.Fatal("configured signing key ignored")
	}
}

func TestExplicitPlatformWinsOverHostOS(t *testing.T) {
	i := (&Config{Platform: MacPlatform}).identityFor("windows")
	if i.Platform != MacPlatform || !strings.Contains(i.UserAgent(), "macOS") {
		t.Fatalf("platform override ignored: %+v", i)
	}
}

func TestAutomaticSTUNSurvivesConfigSave(t *testing.T) {
	cfg := &Config{}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var loaded Config
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatal(err)
	}
	if err := loaded.Validate(); err != nil {
		t.Fatal(err)
	}
	if loaded.Network.STUNServers != nil {
		t.Fatal("config rewrite disabled dynamic STUN discovery")
	}
}

func TestUnboundPlatformSurvivesConfigRoundTrip(t *testing.T) {
	var cfg Config
	if err := json.Unmarshal([]byte(`{"platform":4,"unbound_platform":1,"unbound_client_id":"MG-old","unbound_device_id":"old-device"}`), &cfg); err != nil {
		t.Fatal(err)
	}
	// A different cached platform is valid: registration must replace it when
	// the selected platform changes, rather than losing the old metadata on load.
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var loaded Config
	if err := json.Unmarshal(encoded, &loaded); err != nil {
		t.Fatal(err)
	}
	if loaded.Platform != MacPlatform || loaded.UnboundPlatform != WindowsPlatform || loaded.UnboundClientID != "MG-old" || loaded.UnboundDeviceID != "old-device" {
		t.Fatal("cached platform metadata was lost")
	}
}
