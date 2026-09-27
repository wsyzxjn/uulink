package api

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/wsyzxjn/uulink/pkg/auth"
	"github.com/wsyzxjn/uulink/pkg/settings"
)

func TestConfiguredAPIEndpointAndIdentity(t *testing.T) {
	t.Setenv("UULINK_CLIENT_VN", "")
	t.Setenv("UULINK_CLIENT_VC", "")
	cfg := &auth.Config{
		APIBaseURL: "https://custom.example/", VersionName: "5.2.0", VersionCode: "10000",
		ClientProfile: auth.ClientProfile{Country: "JP", SigningKey: "example-key"},
		Network:       settings.Network{APITimeoutSeconds: 7},
	}
	client := NewClient(cfg)
	if client.http.Timeout != 7*time.Second {
		t.Fatal("HTTP timeout ignored")
	}
	client.http.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != "https://custom.example/api/v1/user/info" {
			t.Fatalf("endpoint ignored: %s", req.URL)
		}
		if !strings.Contains(req.UserAgent(), "UURemote/5.2.0") || req.Header.Get("X-Param-VN") != "5.2.0" || req.Header.Get("X-Param-CNT") != "JP" {
			t.Fatal("identity override ignored")
		}
		headers := map[string]string{}
		for key := range req.Header {
			headers[key] = req.Header.Get(key)
		}
		want := auth.SignWithKey("example-key", req.Method, req.URL.String(), headers, "")
		if req.Header.Get("X-Param-SIGN") != want {
			t.Fatal("signing key ignored")
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"code":0,"data":{"user_id":"test"}}`))}, nil
	})
	if _, err := client.GetUserInfo(); err != nil {
		t.Fatal(err)
	}
}
