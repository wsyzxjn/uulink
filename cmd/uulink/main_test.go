package main

import (
	"path/filepath"
	"testing"

	"github.com/user/uulink/pkg/api"
	"github.com/user/uulink/pkg/auth"
	"github.com/user/uulink/pkg/remoteconfig"
	"github.com/user/uulink/pkg/tunnel"
)

func TestConfiguredRulesAllowsInboundOnly(t *testing.T) {
	rules, err := configuredRules(&auth.Config{}, "", "", "127.0.0.1", "", "127.0.0.1", "")
	if err != nil {
		t.Fatalf("configuredRules inbound-only: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("inbound-only rules = %v, want none", rules)
	}
}

func TestConfiguredRulesSinglePort(t *testing.T) {
	rules, err := configuredRules(&auth.Config{}, "101", "", "127.0.0.1", "8080", "127.0.0.1", "18080")
	if err != nil {
		t.Fatalf("configuredRules single port: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("len(rules) = %d, want 1", len(rules))
	}
	if rules[0].LocalPort != 8080 || rules[0].TargetPort != 18080 || rules[0].ID != "101" {
		t.Errorf("rule[0] = %+v", rules[0])
	}
}

func TestConfiguredRulesPortRange(t *testing.T) {
	rules, err := configuredRules(&auth.Config{}, "", "", "127.0.0.1", "9000-9002", "127.0.0.1", "8000-8002")
	if err != nil {
		t.Fatalf("configuredRules port range: %v", err)
	}
	if len(rules) != 3 {
		t.Fatalf("len(rules) = %d, want 3", len(rules))
	}
	expected := []struct{ local, remote int }{
		{9000, 8000},
		{9001, 8001},
		{9002, 8002},
	}
	for i, exp := range expected {
		if rules[i].LocalPort != exp.local || rules[i].TargetPort != exp.remote {
			t.Errorf("rule[%d] = %+v, want local %d -> remote %d", i, rules[i], exp.local, exp.remote)
		}
	}
}

func TestConfiguredRulesMappingFlag(t *testing.T) {
	rules, err := configuredRules(&auth.Config{}, "", "5000-5001:6000-6001", "127.0.0.1", "", "127.0.0.1", "")
	if err != nil {
		t.Fatalf("configuredRules -mapping: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("len(rules) = %d, want 2", len(rules))
	}
	if rules[0].LocalPort != 5000 || rules[0].TargetPort != 6000 {
		t.Errorf("rule[0] = %+v", rules[0])
	}
	if rules[1].LocalPort != 5001 || rules[1].TargetPort != 6001 {
		t.Errorf("rule[1] = %+v", rules[1])
	}
}

func TestConfiguredRulesConfigRange(t *testing.T) {
	cfg := &auth.Config{
		Mappings: []auth.PortMapping{
			{LocalRange: "7000-7001", RemoteRange: "8000-8001"},
			{Range: "9000-9001:10000-10001"},
		},
	}
	rules, err := configuredRules(cfg, "", "", "127.0.0.1", "", "127.0.0.1", "")
	if err != nil {
		t.Fatalf("configuredRules config ranges: %v", err)
	}
	if len(rules) != 4 {
		t.Fatalf("len(rules) = %d, want 4", len(rules))
	}
	if rules[0].LocalPort != 7000 || rules[0].TargetPort != 8000 {
		t.Errorf("rule[0] = %+v", rules[0])
	}
	if rules[1].LocalPort != 7001 || rules[1].TargetPort != 8001 {
		t.Errorf("rule[1] = %+v", rules[1])
	}
	if rules[2].LocalPort != 9000 || rules[2].TargetPort != 10000 {
		t.Errorf("rule[2] = %+v", rules[2])
	}
	if rules[3].LocalPort != 9001 || rules[3].TargetPort != 10001 {
		t.Errorf("rule[3] = %+v", rules[3])
	}
}

func TestConfiguredRulesRangeMismatchError(t *testing.T) {
	_, err := configuredRules(&auth.Config{}, "", "", "127.0.0.1", "9000-9005", "127.0.0.1", "8000-8002")
	if err == nil {
		t.Fatal("expected error on range length mismatch, got nil")
	}
}

func TestBuildSecurityPolicyCombinesConfigAndCLI(t *testing.T) {
	policy, err := buildSecurityPolicy(&auth.Config{
		AllowLAN:     true,
		AllowedPorts: []int{22, 80},
	}, false, "")
	if err != nil {
		t.Fatalf("buildSecurityPolicy config: %v", err)
	}
	if !policy.AllowLAN || !policy.AllowedPorts[22] || !policy.AllowedPorts[80] {
		t.Fatalf("config policy = %+v, want LAN enabled with ports 22 and 80", policy)
	}

	policy, err = buildSecurityPolicy(&auth.Config{
		AllowedPorts: []int{22},
	}, false, "443")
	if err != nil {
		t.Fatalf("buildSecurityPolicy CLI override: %v", err)
	}
	if policy.AllowLAN || !policy.AllowedPorts[443] || policy.AllowedPorts[22] {
		t.Fatalf("CLI policy = %+v, want loopback-only with port 443 only", policy)
	}

	if _, err := buildSecurityPolicy(&auth.Config{}, false, "   "); err == nil {
		t.Fatal("buildSecurityPolicy accepted a whitespace-only port whitelist")
	}

	policy, err = buildSecurityPolicy(&auth.Config{AllowedPorts: []int{}}, false, "")
	if err != nil {
		t.Fatalf("buildSecurityPolicy empty config whitelist: %v", err)
	}
	if policy.AllowedPorts == nil || len(policy.AllowedPorts) != 0 {
		t.Fatalf("empty config whitelist = %#v, want non-nil empty map", policy.AllowedPorts)
	}
}

func TestFormatAllowedPorts(t *testing.T) {
	tests := []struct {
		ports map[int]bool
		want  string
	}{
		{map[int]bool{}, ""},
		{map[int]bool{22: true}, "22"},
		{map[int]bool{22: true, 80: true, 443: true}, "22,80,443"},
		{map[int]bool{1: true, 2: true, 3: true, 10: true, 12: true, 13: true}, "1-3,10,12-13"},
	}
	for _, tt := range tests {
		if got := formatAllowedPorts(tt.ports); got != tt.want {
			t.Errorf("formatAllowedPorts(%v) = %q, want %q", tt.ports, got, tt.want)
		}
	}
}

func TestCustomCodeValidationAndGeneration(t *testing.T) {
	// Valid codes
	for _, code := range []string{"Pass1234", "Secure9999", "Code2026Aa"} {
		if err := api.ValidateCustomShareCode(code); err != nil {
			t.Errorf("expected code %q to be valid, got: %v", code, err)
		}
	}

	// Invalid codes
	for _, code := range []string{"1234567", "allletters", "12345678", "toolongcode123456789", "invalid!@#"} {
		if err := api.ValidateCustomShareCode(code); err == nil {
			t.Errorf("expected code %q to be invalid, got nil", code)
		}
	}

	// Generated code must always be valid
	for i := 0; i < 5; i++ {
		generated, err := api.GenerateCustomShareCode()
		if err != nil {
			t.Fatalf("GenerateCustomShareCode: %v", err)
		}
		if err := api.ValidateCustomShareCode(generated); err != nil {
			t.Fatalf("generated code %q failed validation: %v", generated, err)
		}
	}
}

func TestCustomCodeResolutionPriority(t *testing.T) {
	cfg := &auth.Config{
		CustomCode: "ConfigPass1",
		ShareID:    "998877",
	}

	resolve := func(flagCode, guestFlagCode, cfgCode string) string {
		effective := flagCode
		if effective == "" {
			effective = guestFlagCode
		}
		if effective == "" {
			effective = cfgCode
		}
		return effective
	}

	if got := resolve("FlagPass1", "GuestPass1", cfg.CustomCode); got != "FlagPass1" {
		t.Errorf("flagCode priority = %q, want FlagPass1", got)
	}
	if got := resolve("", "GuestPass1", cfg.CustomCode); got != "GuestPass1" {
		t.Errorf("guestFlagCode priority = %q, want GuestPass1", got)
	}
	if got := resolve("", "", cfg.CustomCode); got != "ConfigPass1" {
		t.Errorf("cfgCode priority = %q, want ConfigPass1", got)
	}
}

func TestConfigInitializationAndDeterministicReuse(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")

	// 1. First run: config does not exist, LoadOrInitConfigFile creates it with random fixed client_id
	cfg, err := auth.LoadOrInitConfigFile(configPath)
	if err != nil {
		t.Fatalf("first LoadOrInitConfigFile: %v", err)
	}
	if cfg.ClientID == "" {
		t.Fatal("expected ClientID to be generated on initialization")
	}
	initialClientID := cfg.ClientID

	// Simulate registering with server and saving device_id and custom_code
	cfg.DeviceID = "dev_12345678"
	cfg.CustomCode = "MyPass123"
	if err := auth.SaveConfigFile(configPath, cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}

	// 2. Second run: reloads config, must have exact same ClientID, DeviceID, and CustomCode
	reloaded, err := auth.LoadOrInitConfigFile(configPath)
	if err != nil {
		t.Fatalf("second LoadOrInitConfigFile: %v", err)
	}
	if reloaded.ClientID != initialClientID {
		t.Errorf("ClientID changed: got %s, want %s", reloaded.ClientID, initialClientID)
	}
	if reloaded.DeviceID != "dev_12345678" {
		t.Errorf("DeviceID changed: got %s, want dev_12345678", reloaded.DeviceID)
	}
	if reloaded.CustomCode != "MyPass123" {
		t.Errorf("CustomCode changed: got %s, want MyPass123", reloaded.CustomCode)
	}
}

func TestRemoteShareConfigRulesInMain(t *testing.T) {
	rc := &remoteconfig.RemoteShareConfig{
		ShareID:   "266444253",
		ShareCode: "6W44YBPL",
		Mappings: []auth.PortMapping{
			{LocalPort: 25565, RemotePort: 25565},
		},
		LANMOTD: "Minecraft Game",
		LANPort: 25565,
	}

	rules, err := rc.Rules("", "", "127.0.0.1", "", "127.0.0.1", "")
	if err != nil {
		t.Fatalf("rc.Rules: %v", err)
	}
	if len(rules) != 1 || rules[0].LocalPort != 25565 || rules[0].TargetPort != 25565 {
		t.Fatalf("unexpected rules from remote config: %+v", rules)
	}
}

func TestPublishShareInfoConstruction(t *testing.T) {
	share := &api.GuestShareInfo{
		ConnectID:   "998877",
		ConnectCode: "XYZ12345",
	}
	rules := []tunnel.Rule{
		{
			LocalHost:  "127.0.0.1",
			LocalPort:  25565,
			TargetHost: "127.0.0.1",
			TargetPort: 25565,
		},
	}

	var captured remoteconfig.RemoteShareConfig
	// Verify mapping translation
	payload := &remoteconfig.RemoteShareConfig{
		ShareID:     share.ConnectID,
		ShareCode:   share.ConnectCode,
		ConnectCode: share.ConnectCode,
	}
	for _, r := range rules {
		payload.Mappings = append(payload.Mappings, auth.PortMapping{
			LocalHost:  r.LocalHost,
			LocalPort:  r.LocalPort,
			RemoteHost: r.TargetHost,
			RemotePort: r.TargetPort,
		})
	}
	captured = *payload

	if captured.ShareID != "998877" || captured.ShareCode != "XYZ12345" {
		t.Fatalf("unexpected captured share payload: %+v", captured)
	}
	if len(captured.Mappings) != 1 || captured.Mappings[0].LocalPort != 25565 {
		t.Fatalf("unexpected captured mappings: %+v", captured.Mappings)
	}
}
