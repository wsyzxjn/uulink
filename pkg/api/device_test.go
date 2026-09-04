package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/user/uulink/pkg/auth"
)

type mockRoundTripper func(req *http.Request) (*http.Response, error)

func (f mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestInitWindowsDeviceWithoutAuthReusesClientID(t *testing.T) {
	configuredID := "11223344-5566-7788-99AA-BBCCDDEEFF00"
	expectedGUID := "11223344-5566-7788-99aa-bbccddeeff00"
	expectedClientID := "MG-" + expectedGUID

	var capturedBody map[string]any

	mockTransport := mockRoundTripper(func(req *http.Request) (*http.Response, error) {
		bodyBytes, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if err := json.Unmarshal(bodyBytes, &capturedBody); err != nil {
			t.Fatalf("unmarshal captured body: %v", err)
		}

		respData, _ := json.Marshal(map[string]any{
			"code": 0,
			"msg":  "success",
			"data": map[string]any{
				"device_id": "test_dev_12345678",
			},
		})
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewReader(respData)),
		}, nil
	})

	cfg := &auth.Config{
		UnboundClientID: configuredID,
	}
	client := NewClient(cfg)
	client.http.Transport = mockTransport

	identity, err := client.InitWindowsDeviceWithoutAuth("TestHost")
	if err != nil {
		t.Fatalf("InitWindowsDeviceWithoutAuth: %v", err)
	}

	if identity.ClientID != expectedClientID {
		t.Errorf("identity.ClientID = %q, want %q", identity.ClientID, expectedClientID)
	}
	if identity.DeviceID != "test_dev_12345678" {
		t.Errorf("identity.DeviceID = %q, want test_dev_12345678", identity.DeviceID)
	}

	if capturedBody["client_id"] != expectedClientID {
		t.Errorf("captured body client_id = %v, want %s", capturedBody["client_id"], expectedClientID)
	}
	if capturedBody["machine_guid"] != expectedGUID {
		t.Errorf("captured body machine_guid = %v, want %s", capturedBody["machine_guid"], expectedGUID)
	}
	if capturedBody["guid"] != expectedGUID {
		t.Errorf("captured body guid = %v, want %s", capturedBody["guid"], expectedGUID)
	}

	// Verify that client.cfg.DeviceID was populated
	if cfg.UnboundDeviceID != "test_dev_12345678" {
		t.Errorf("cfg.DeviceID was not populated: %q", cfg.DeviceID)
	}
}

func TestInitWindowsDeviceWithoutAuthGeneratesWhenEmpty(t *testing.T) {
	mockTransport := mockRoundTripper(func(req *http.Request) (*http.Response, error) {
		respData, _ := json.Marshal(map[string]any{
			"code": 0,
			"msg":  "success",
			"data": map[string]any{
				"device_id": "gen_dev_87654321",
			},
		})
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(bytes.NewReader(respData)),
		}, nil
	})

	cfg := &auth.Config{}
	client := NewClient(cfg)
	client.http.Transport = mockTransport

	identity, err := client.InitWindowsDeviceWithoutAuth("TestHost")
	if err != nil {
		t.Fatalf("InitWindowsDeviceWithoutAuth: %v", err)
	}

	if cfg.UnboundClientID == "" {
		t.Fatal("cfg.ClientID was not generated and set")
	}
	if identity.DeviceID != "gen_dev_87654321" {
		t.Errorf("identity.DeviceID = %q, want gen_dev_87654321", identity.DeviceID)
	}
}
