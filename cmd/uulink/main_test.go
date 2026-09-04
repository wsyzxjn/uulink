package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/user/uulink/pkg/api"
	"github.com/user/uulink/pkg/auth"
	"github.com/user/uulink/pkg/peer"
	"github.com/user/uulink/pkg/remoteconfig"
	"github.com/user/uulink/pkg/tunnel"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func loginTestClient(cfg *auth.Config, response string) *api.Client {
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(response)),
			Header:     make(http.Header),
		}, nil
	})
	return api.NewClientWithOptions(cfg, api.ClientOptions{
		BaseURL:    "https://api.example",
		HTTPClient: &http.Client{Transport: transport},
	})
}

func unsignedTestJWT(subject string) string {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"` + subject + `"}`))
	return "header." + payload + ".signature"
}

func TestValidateTransportForServer(t *testing.T) {
	if err := validateTransportForServer(peer.TransportAuto, true); err != nil {
		t.Fatalf("server mode rejected auto transport: %v", err)
	}
	if err := validateTransportForServer(peer.TransportRelay, false); err != nil {
		t.Fatalf("controller mode rejected relay transport: %v", err)
	}
	if err := validateTransportForServer(peer.TransportRelay, true); err == nil {
		t.Fatal("server mode accepted relay transport")
	}
}

func TestPersistLogin(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		cfg := &auth.Config{JWT: "old-token", UserID: "old-user", GuestID: "old-guest"}
		client := loginTestClient(cfg, `{"code":0,"data":{"user_id":"new-user","nickname":"tester"}}`)
		configPath := filepath.Join(t.TempDir(), "config.json")

		state, err := persistLogin(client, cfg, configPath, unsignedTestJWT("new-user"))
		if err != nil {
			t.Fatalf("persistLogin(): %v", err)
		}
		if !state.Valid || cfg.UserID != "new-user" || cfg.GuestID != "" {
			t.Fatalf("persisted state=%+v config=%+v", state, cfg)
		}
		saved, err := auth.LoadConfigFile(configPath)
		if err != nil {
			t.Fatalf("LoadConfigFile(): %v", err)
		}
		if saved.JWT != cfg.JWT || saved.UserID != "new-user" || saved.GuestID != "" {
			t.Fatalf("saved config=%+v", saved)
		}
		info, err := os.Stat(configPath)
		if err != nil {
			t.Fatalf("Stat(): %v", err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("config permissions=%o, want 600", info.Mode().Perm())
		}
	})

	t.Run("invalid login rolls back", func(t *testing.T) {
		cfg := &auth.Config{JWT: "old-token", UserID: "old-user", GuestID: "old-guest"}
		client := loginTestClient(cfg, `{"code":0,"data":{}}`)
		configPath := filepath.Join(t.TempDir(), "config.json")

		if _, err := persistLogin(client, cfg, configPath, unsignedTestJWT("new-user")); err == nil {
			t.Fatal("persistLogin() accepted an invalid login state")
		}
		if cfg.JWT != "old-token" || cfg.UserID != "old-user" || cfg.GuestID != "old-guest" {
			t.Fatalf("config was not rolled back: %+v", cfg)
		}
		if _, err := os.Stat(configPath); !os.IsNotExist(err) {
			t.Fatalf("invalid login wrote config: %v", err)
		}
	})

	t.Run("save failure rolls back", func(t *testing.T) {
		cfg := &auth.Config{JWT: "old-token", UserID: "old-user", GuestID: "old-guest"}
		client := loginTestClient(cfg, `{"code":0,"data":{"user_id":"new-user"}}`)
		configPath := filepath.Join(t.TempDir(), "missing", "config.json")

		if _, err := persistLogin(client, cfg, configPath, unsignedTestJWT("new-user")); err == nil {
			t.Fatal("persistLogin() succeeded with a missing config directory")
		}
		if cfg.JWT != "old-token" || cfg.UserID != "old-user" || cfg.GuestID != "old-guest" {
			t.Fatalf("config was not rolled back: %+v", cfg)
		}
	})
}

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

func TestDetermineTargetSessions(t *testing.T) {
	// 1. Default when both are zero
	if s := determineTargetSessions(0, 0); s != 4 {
		t.Errorf("expected default 4, got %d", s)
	}

	// 2. Config overrides default when flag is zero
	if s := determineTargetSessions(0, 2); s != 2 {
		t.Errorf("expected config 2, got %d", s)
	}

	// 3. CLI flag overrides config
	if s := determineTargetSessions(8, 2); s != 8 {
		t.Errorf("expected CLI flag 8, got %d", s)
	}

	// 4. User explicitly disables with 1
	if s := determineTargetSessions(1, 4); s != 1 {
		t.Errorf("expected disabled 1, got %d", s)
	}
}

func TestMultiSessionShares(t *testing.T) {
	t.Run("single share is not pooled", func(t *testing.T) {
		shares, err := multiSessionShares("", true, false, "abc", "123456")
		if err != nil || len(shares) != 0 {
			t.Fatalf("shares=%v err=%v, want none", shares, err)
		}
	})

	t.Run("comma separated flags", func(t *testing.T) {
		shares, err := multiSessionShares("", true, false, "a1, a2 ,a3", "c1,c2,c3")
		if err != nil {
			t.Fatalf("multiSessionShares(): %v", err)
		}
		want := []shareEntry{{ID: "a1", Code: "c1"}, {ID: "a2", Code: "c2"}, {ID: "a3", Code: "c3"}}
		if len(shares) != len(want) {
			t.Fatalf("shares=%v, want %v", shares, want)
		}
		for i := range want {
			if shares[i] != want[i] {
				t.Fatalf("shares[%d]=%v, want %v", i, shares[i], want[i])
			}
		}
	})

	t.Run("mismatched counts", func(t *testing.T) {
		if _, err := multiSessionShares("", true, false, "a1,a2", "c1"); err == nil {
			t.Fatal("mismatched ID/code counts were accepted")
		}
		if _, err := multiSessionShares("", true, false, "a1,,a3", "c1,c2,c3"); err == nil {
			t.Fatal("empty share ID was accepted")
		}
	})

	t.Run("room file formats", func(t *testing.T) {
		dir := t.TempDir()
		multi := filepath.Join(dir, "multi.json")
		if err := os.WriteFile(multi, []byte(`[{"connect_id":"a1","connect_code":"c1"},{"connect_id":"a2","connect_code":"c2"}]`), 0600); err != nil {
			t.Fatal(err)
		}
		shares, err := multiSessionShares(multi, true, false, "", "")
		if err != nil || len(shares) != 2 || shares[1].ID != "a2" || shares[1].Code != "c2" {
			t.Fatalf("multi-share file: shares=%v err=%v", shares, err)
		}

		single := filepath.Join(dir, "single.json")
		if err := os.WriteFile(single, []byte(`{"connect_id":"a1","connect_code":"c1"}`), 0600); err != nil {
			t.Fatal(err)
		}
		shares, err = multiSessionShares(single, false, true, "", "")
		if err != nil || len(shares) != 1 || shares[0].ID != "a1" {
			t.Fatalf("single-share file: shares=%v err=%v", shares, err)
		}

		if _, err := multiSessionShares(filepath.Join(dir, "missing.json"), true, false, "", ""); err == nil {
			t.Fatal("missing room file was accepted")
		}
	})
}

func TestFirstNonEmpty(t *testing.T) {
	if got := firstNonEmpty("", "", "third"); got != "third" {
		t.Fatalf("firstNonEmpty() = %q, want third", got)
	}
	if got := firstNonEmpty("first", "second"); got != "first" {
		t.Fatalf("firstNonEmpty() = %q, want first", got)
	}
	if got := firstNonEmpty(); got != "" {
		t.Fatalf("firstNonEmpty() = %q, want empty", got)
	}
}

func TestPublishShareInfoPostsRemoteConfig(t *testing.T) {
	var (
		method   string
		auth     string
		received remoteconfig.RemoteShareConfig
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		auth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode publish payload: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	share := &api.GuestShareInfo{ConnectID: "998877", ConnectCode: "XYZ12345"}
	rules := []tunnel.Rule{{LocalHost: "127.0.0.1", LocalPort: 25565, TargetHost: "127.0.0.1", TargetPort: 25566}}
	if err := publishShareInfo(server.URL, "secret-token", share, rules); err != nil {
		t.Fatalf("publishShareInfo(): %v", err)
	}
	if method != http.MethodPost || auth != "Bearer secret-token" {
		t.Fatalf("request method=%q auth=%q", method, auth)
	}
	if received.ShareID != "998877" || received.ShareCode != "XYZ12345" || received.UpdatedAt == "" {
		t.Fatalf("payload = %+v", received)
	}
	if len(received.Mappings) != 1 || received.Mappings[0].LocalPort != 25565 || received.Mappings[0].RemotePort != 25566 {
		t.Fatalf("payload mappings = %+v", received.Mappings)
	}
	if err := received.Validate(); err != nil {
		t.Fatalf("published document is not a valid remote config: %v", err)
	}
}

func TestPublishShareInfoReportsHTTPFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	defer server.Close()

	err := publishShareInfo(server.URL, "", &api.GuestShareInfo{ConnectID: "1", ConnectCode: "2"}, nil)
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("publishShareInfo() error = %v, want HTTP 403 failure", err)
	}
}
