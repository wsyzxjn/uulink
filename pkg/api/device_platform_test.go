package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/wsyzxjn/uulink/pkg/auth"
)

func TestDeviceRegistrationUsesConfiguredPlatform(t *testing.T) {
	for _, platform := range []int{auth.WindowsPlatform, auth.MacPlatform} {
		for _, unbound := range []bool{false, true} {
			t.Run(strconv.Itoa(platform)+"/unbound="+strconv.FormatBool(unbound), func(t *testing.T) {
				clientID := "11223344-5566-7788-99aa-bbccddeeff00"
				path, controllable := "/api/v1/device/macos/init", "/api/v1/device/mac_controllable"
				if platform == auth.WindowsPlatform {
					clientID = "MG-" + clientID
					path, controllable = "/api/v1/device/windows/init", "/api/v1/device/controllable"
				}
				cfg := &auth.Config{Platform: platform, ClientID: clientID, DeviceID: "bound-device", JWT: "account-token", UserID: "account-user", UnboundClientID: clientID}
				cfg.Devices.Mac.CPU, cfg.Devices.Windows.CPU = "mac-profile", "windows-profile"
				calls := 0
				client := NewClientWithOptions(cfg, ClientOptions{HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					calls++
					if req.Header.Get("X-Param-PLAT") != strconv.Itoa(platform) {
						t.Fatalf("wrong platform header: %s", req.Header.Get("X-Param-PLAT"))
					}
					if calls == 1 {
						if req.URL.Path != path {
							t.Fatalf("registration path=%s, want %s", req.URL.Path, path)
						}
						if unbound && (req.Header.Get("Authorization") != "" || req.Header.Get("X-Param-user-id") != "" || req.Header.Get("X-Param-device-id") != "") {
							t.Fatal("unbound registration leaked the account identity")
						}
						if !unbound && req.Header.Get("Authorization") != "Bearer account-token" {
							t.Fatal("bound registration lost login state")
						}
						var body map[string]any
						if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
							t.Fatal(err)
						}
						if body["client_id"] != clientID || body["system_id"] != clientID {
							t.Fatal("registration identity changed")
						}
						wantCPU := "mac-profile"
						if platform == auth.WindowsPlatform {
							wantCPU = "windows-profile"
							if body["guid"] != strings.TrimPrefix(clientID, "MG-") {
								t.Fatal("missing Windows GUID")
							}
						}
						if body["cpu"] != wantCPU {
							t.Fatalf("wrong device profile: %v", body["cpu"])
						}
					} else if req.URL.Path != controllable {
						t.Fatalf("controllable path=%s, want %s", req.URL.Path, controllable)
					}
					return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"code":0,"data":{"device_id":"registered-device"}}`))}, nil
				})}})
				var identity *DeviceIdentity
				var err error
				if unbound {
					identity, err = client.InitDeviceWithoutAuthContext(context.Background(), "test")
				} else {
					identity, err = client.InitDeviceContext(context.Background(), "test")
				}
				if err != nil {
					t.Fatal(err)
				}
				if identity.Platform != platform || identity.DeviceID != "registered-device" {
					t.Fatalf("unexpected identity: %+v", identity)
				}
				if unbound {
					if cfg.DeviceID != "bound-device" || cfg.JWT != "account-token" || cfg.UnboundPlatform != platform || cfg.UnboundDeviceID != identity.DeviceID {
						t.Fatal("unbound registration changed the logged-in identity or lost platform")
					}
				} else if cfg.DeviceID != identity.DeviceID || cfg.Platform != platform {
					t.Fatal("registered identity was not adopted")
				}
				if _, err := client.SetDeviceControllableContext(context.Background(), true); err != nil {
					t.Fatal(err)
				}
				if calls != 2 {
					t.Fatalf("requests=%d", calls)
				}
			})
		}
	}
}

func TestUnboundPlatformSwitchRotatesOnlyUnboundIdentity(t *testing.T) {
	for _, platform := range []int{auth.WindowsPlatform, auth.MacPlatform} {
		oldID, oldPlatform := "11223344-5566-7788-99aa-bbccddeeff00", auth.MacPlatform
		if platform == auth.MacPlatform {
			oldID, oldPlatform = "MG-"+oldID, auth.WindowsPlatform
		}
		cfg := &auth.Config{Platform: platform, ClientID: "account-client", DeviceID: "account-device", UnboundClientID: oldID, UnboundDeviceID: "old-device", UnboundPlatform: oldPlatform}
		client := NewClientWithOptions(cfg, ClientOptions{HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"code":0,"data":{"device_id":"new-device"}}`))}, nil
		})}})
		first, err := client.InitDeviceWithoutAuthContext(context.Background(), "test")
		if err != nil {
			t.Fatal(err)
		}
		if first.ClientID == oldID || first.Platform != platform || strings.HasPrefix(first.ClientID, "MG-") != (platform == auth.WindowsPlatform) {
			t.Fatal("platform switch reused an incompatible client ID")
		}
		second, err := client.InitDeviceWithoutAuthContext(context.Background(), "test")
		if err != nil {
			t.Fatal(err)
		}
		if first.ClientID != second.ClientID || cfg.ClientID != "account-client" || cfg.DeviceID != "account-device" {
			t.Fatal("identity was not stable or account identity changed")
		}
	}
}

func TestFailedRegistrationPreservesIdentity(t *testing.T) {
	cfg := &auth.Config{Platform: auth.MacPlatform, ClientID: "MG-11223344-5566-7788-99aa-bbccddeeff00", DeviceID: "old", UnboundClientID: "MG-11223344-5566-7788-99aa-bbccddeeff00", UnboundPlatform: auth.WindowsPlatform}
	before := *cfg
	client := NewClientWithOptions(cfg, ClientOptions{HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("X-Param-device-id") != "" {
			t.Fatal("platform switch sent the old device ID with a new client ID")
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"code":1001,"msg":"rejected"}`))}, nil
	})}})
	if _, err := client.InitDeviceContext(context.Background(), "test"); err == nil {
		t.Fatal("expected error")
	}
	if !reflect.DeepEqual(before, *cfg) {
		t.Fatal("failed bound registration replaced the identity")
	}
	if _, err := client.InitDeviceWithoutAuthContext(context.Background(), "test"); err == nil {
		t.Fatal("expected error")
	}
	if !reflect.DeepEqual(before, *cfg) {
		t.Fatal("failed unbound registration replaced the identity")
	}
}

func TestGuestRequestsRetainRegisteredPlatform(t *testing.T) {
	for _, platform := range []int{auth.WindowsPlatform, auth.MacPlatform} {
		cfg := &auth.Config{Platform: platform}
		payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"guest-user","device_id":"guest-device"}`))
		client := NewClientWithOptions(cfg, ClientOptions{HTTPClient: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.Header.Get("X-Param-PLAT") != strconv.Itoa(platform) {
				t.Fatal("guest request lost its registered platform")
			}
			body := `{"code":0,"data":{"device_id":"guest-device"}}`
			if req.URL.Path == "/api/v1/guest/create" {
				body = `{"code":0,"data":{"guest_id":"guest","token":"header.` + payload + `.signature"}}`
			}
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
		})}})
		session, identity, err := client.CreateUnboundGuestContext(context.Background(), "test")
		if err != nil {
			t.Fatal(err)
		}
		if session.Platform != platform || identity.Platform != platform {
			t.Fatal("platform not carried by guest session")
		}
		if platform == auth.WindowsPlatform {
			cfg.Platform = auth.MacPlatform
		} else {
			cfg.Platform = auth.WindowsPlatform
		}
		if _, err := client.GuestSetDeviceControllableContext(context.Background(), session, true); err != nil {
			t.Fatal(err)
		}
	}
}
