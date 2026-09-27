//go:build integration

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wsyzxjn/uulink/pkg/api"
	"github.com/wsyzxjn/uulink/pkg/remoteconfig"
	"github.com/wsyzxjn/uulink/pkg/tunnel"
)

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
	if err := publishShareInfo(context.Background(), server.URL, "secret-token", share, rules); err != nil {
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

	err := publishShareInfo(context.Background(), server.URL, "", &api.GuestShareInfo{ConnectID: "1", ConnectCode: "2"}, nil)
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("publishShareInfo() error = %v, want HTTP 403 failure", err)
	}
}
