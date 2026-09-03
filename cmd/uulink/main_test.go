package main

import (
	"testing"

	"github.com/user/uulink/pkg/auth"
)

func TestConfiguredRulesAllowsInboundOnly(t *testing.T) {
	rules, err := configuredRules(&auth.Config{}, "", "127.0.0.1", 0, "127.0.0.1", 0)
	if err != nil {
		t.Fatalf("configuredRules inbound-only: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("inbound-only rules = %v, want none", rules)
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
