package remoteconfig

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"net/http"
	"testing"

	"github.com/user/uulink/pkg/auth"
)

type roundTripperFunc func(req *http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestFetchAndValidate(t *testing.T) {
	fakeClient := &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			if req.Method != "GET" {
				return &http.Response{
					StatusCode: http.StatusMethodNotAllowed,
					Body:       io.NopCloser(bytes.NewReader(nil)),
				}, nil
			}
			data, _ := json.Marshal(map[string]any{
				"share_id":   "266444253",
				"share_code": "6W44YBPL",
				"mappings": []map[string]any{
					{"local_port": 25565, "remote_port": 25565},
				},
				"lan_motd": "Minecraft Test",
				"lan_port": 25565,
			})
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(bytes.NewReader(data)),
			}, nil
		}),
	}

	cfg, err := FetchWithClient(fakeClient, "https://example.com/room.json")
	if err != nil {
		t.Fatalf("fetch remote config: %v", err)
	}

	if cfg.EffectiveShareID() != "266444253" || cfg.EffectiveShareCode() != "6W44YBPL" {
		t.Fatalf("unexpected share credentials: id=%s code=%s", cfg.EffectiveShareID(), cfg.EffectiveShareCode())
	}
	if cfg.LANMOTD != "Minecraft Test" || cfg.LANPort != 25565 {
		t.Errorf("unexpected lan fields: motd=%s port=%d", cfg.LANMOTD, cfg.LANPort)
	}

	rules, err := cfg.Rules("", "", "127.0.0.1", "", "127.0.0.1", "")
	if err != nil {
		t.Fatalf("cfg.Rules: %v", err)
	}
	if len(rules) != 1 || rules[0].LocalPort != 25565 || rules[0].TargetPort != 25565 {
		t.Fatalf("unexpected rules: %+v", rules)
	}
}

func TestPublish(t *testing.T) {
	var receivedHeader string
	var receivedBody RemoteShareConfig

	fakeClient := &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			if req.Method != "POST" {
				return &http.Response{
					StatusCode: http.StatusMethodNotAllowed,
					Body:       io.NopCloser(bytes.NewReader(nil)),
				}, nil
			}
			receivedHeader = req.Header.Get("Authorization")
			if err := json.NewDecoder(req.Body).Decode(&receivedBody); err != nil {
				return &http.Response{
					StatusCode: http.StatusBadRequest,
					Body:       io.NopCloser(bytes.NewReader(nil)),
				}, nil
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(nil)),
			}, nil
		}),
	}

	cfg := &RemoteShareConfig{
		ShareID:   "100200",
		ShareCode: "ABCDEFGH",
		Mappings: []auth.PortMapping{
			{LocalPort: 8080, RemotePort: 80},
		},
	}

	err := PublishWithClient(fakeClient, "https://example.com/sync", "secret123", cfg)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}

	if receivedHeader != "Bearer secret123" {
		t.Errorf("authorization header = %q, want %q", receivedHeader, "Bearer secret123")
	}
	if receivedBody.ShareID != "100200" || receivedBody.ShareCode != "ABCDEFGH" {
		t.Errorf("received body = %+v, want share id/code", receivedBody)
	}
}

func TestRulesWithMappingOverride(t *testing.T) {
	cfg := &RemoteShareConfig{
		ShareID:   "123",
		ShareCode: "456",
		Mapping:   "9000-9001:8000-8001",
	}

	rules, err := cfg.Rules("", "", "127.0.0.1", "", "127.0.0.1", "")
	if err != nil {
		t.Fatalf("rules from mapping string: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("len(rules) = %d, want 2", len(rules))
	}

	// CLI mapping override
	rules2, err := cfg.Rules("", "7000:6000", "127.0.0.1", "", "127.0.0.1", "")
	if err != nil {
		t.Fatalf("rules with CLI override: %v", err)
	}
	if len(rules2) != 1 || rules2[0].LocalPort != 7000 {
		t.Fatalf("unexpected rules2: %+v", rules2)
	}
}

func TestFetchCustomCodeAndDeviceID(t *testing.T) {
	fakeClient := &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			data, _ := json.Marshal(map[string]any{
				"device_id":   "aeawn7l56uabjgfc",
				"custom_code": "SecretPass123",
				"mappings": []map[string]any{
					{"local_port": 2222, "remote_port": 22},
				},
			})
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(bytes.NewReader(data)),
			}, nil
		}),
	}

	cfg, err := FetchWithClient(fakeClient, "https://example.com/static-room.json")
	if err != nil {
		t.Fatalf("fetch static config: %v", err)
	}

	if cfg.EffectiveShareID() != "aeawn7l56uabjgfc" {
		t.Errorf("EffectiveShareID = %q, want aeawn7l56uabjgfc", cfg.EffectiveShareID())
	}
	if cfg.EffectiveShareCode() != "SecretPass123" {
		t.Errorf("EffectiveShareCode = %q, want SecretPass123", cfg.EffectiveShareCode())
	}
}

func TestFetchLocalFile(t *testing.T) {
	dir := t.TempDir()
	filePath := dir + "/local-room.json"

	data, _ := json.Marshal(map[string]any{
		"share_id":   "888999",
		"share_code": "Pass1234",
	})
	if err := os.WriteFile(filePath, data, 0600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	cfg, err := Fetch(filePath, 0)
	if err != nil {
		t.Fatalf("Fetch local file: %v", err)
	}
	if cfg.EffectiveShareID() != "888999" || cfg.EffectiveShareCode() != "Pass1234" {
		t.Fatalf("unexpected fetched config: %+v", cfg)
	}

	// Test file:// prefix
	cfg2, err := Fetch("file://"+filePath, 0)
	if err != nil {
		t.Fatalf("Fetch file:// prefix: %v", err)
	}
	if cfg2.EffectiveShareID() != "888999" {
		t.Fatalf("unexpected fetched config: %+v", cfg2)
	}
}
