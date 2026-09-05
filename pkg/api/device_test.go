package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/wsyzxjn/uulink/pkg/auth"
)

func windowsInitTestClient(t *testing.T, cfg *auth.Config, captured *map[string]any) *Client {
	t.Helper()
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path != "/api/v1/device/windows/init" {
			t.Fatalf("unexpected request path %q", request.URL.Path)
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if err := json.Unmarshal(body, captured); err != nil {
			t.Fatalf("unmarshal captured body: %v", err)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"code":0,"msg":"success","data":{"device_id":"test_dev_12345678"}}`)),
		}, nil
	})
	return NewClientWithOptions(cfg, ClientOptions{
		BaseURL:    "https://api.example",
		HTTPClient: &http.Client{Transport: transport},
	})
}

func TestInitWindowsDeviceWithoutAuthReusesClientID(t *testing.T) {
	cfg := &auth.Config{UnboundClientID: "MG-11223344-5566-7788-99AA-BBCCDDEEFF00"}
	var captured map[string]any
	client := windowsInitTestClient(t, cfg, &captured)

	identity, err := client.InitWindowsDeviceWithoutAuth("TestHost")
	if err != nil {
		t.Fatalf("InitWindowsDeviceWithoutAuth: %v", err)
	}

	wantGUID := "11223344-5566-7788-99aa-bbccddeeff00"
	wantClientID := "MG-" + wantGUID
	if identity.ClientID != wantClientID || identity.DeviceID != "test_dev_12345678" {
		t.Fatalf("identity = %+v", identity)
	}
	if captured["client_id"] != wantClientID || captured["machine_guid"] != wantGUID || captured["guid"] != wantGUID {
		t.Fatalf("request body = %v", captured)
	}
	if cfg.UnboundClientID != wantClientID || cfg.UnboundDeviceID != "test_dev_12345678" {
		t.Fatalf("config identity not persisted: %+v", cfg)
	}
}

func TestInitWindowsDeviceWithoutAuthGeneratesIdentityWhenEmpty(t *testing.T) {
	cfg := &auth.Config{ClientID: "config-client"}
	var captured map[string]any
	client := windowsInitTestClient(t, cfg, &captured)

	identity, err := client.InitWindowsDeviceWithoutAuth("TestHost")
	if err != nil {
		t.Fatalf("InitWindowsDeviceWithoutAuth: %v", err)
	}
	if !strings.HasPrefix(identity.ClientID, "MG-") || identity.ClientID == "MG-" {
		t.Fatalf("generated client id = %q", identity.ClientID)
	}
	if cfg.UnboundClientID != identity.ClientID || cfg.UnboundDeviceID != identity.DeviceID {
		t.Fatalf("config identity not persisted: %+v", cfg)
	}
	// The logged-in identity of the config is untouched.
	if cfg.ClientID != "config-client" || cfg.DeviceID != "" {
		t.Fatalf("logged-in identity changed: %+v", cfg)
	}
}
