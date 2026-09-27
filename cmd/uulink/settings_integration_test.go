//go:build integration

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/wsyzxjn/uulink/pkg/api"
	"github.com/wsyzxjn/uulink/pkg/auth"
)

func TestConfigReachesSignalingAndACKsDoNotCollide(t *testing.T) {
	t.Setenv("UULINK_STREAMER_VERSION", "")
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"streamer_version":"V7.0.0","client_profile":{"websocket_user_agent":"test-client"},"network":{"stun_servers":[]}}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := auth.LoadConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	headers := make(chan http.Header, 1)
	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers <- r.Header.Clone()
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.WriteMessage(websocket.TextMessage, []byte(`0{"sid":"test","pingInterval":60000,"pingTimeout":60000}`))
		for {
			kind, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if kind != websocket.TextMessage {
				continue
			}
			text := string(data)
			if text == "40" {
				_ = conn.WriteMessage(websocket.TextMessage, []byte(`40{"sid":"test"}`))
				continue
			}
			if strings.HasPrefix(text, "451-") {
				prefix, _, _ := strings.Cut(strings.TrimPrefix(text, "451-"), "[")
				id, err := strconv.Atoi(prefix)
				if err != nil {
					return
				}
				for offset := range 2 {
					_ = conn.WriteMessage(websocket.TextMessage, fmt.Appendf(nil, "43%d[%d]", id+offset, id+offset))
				}
			}
		}
	}))
	defer server.Close()
	sig, err := connectSignaling(&api.RoomConnectionInfo{SignalingServer: "ws" + strings.TrimPrefix(server.URL, "http")}, true, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer sig.Close()
	h := <-headers
	if h.Get("streamer_version") != "V7.0.0" || h.Get("User-Agent") != "test-client" {
		t.Fatalf("config did not reach gateway: %+v", h)
	}
	for range 7 {
		if _, err := sig.EmitWithAck("before", nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	replies := make(chan int, 2)
	err = sig.EmitBinaryWithAckCount("control", nil, []byte("payload"), 2, func(values []json.RawMessage) {
		var id int
		if len(values) == 1 && json.Unmarshal(values[0], &id) == nil {
			replies <- id
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	next, err := sig.EmitWithAck("after", nil, nil)
	if err != nil || next != 10 {
		t.Fatalf("next ACK %d, err=%v; want 10", next, err)
	}
	for _, want := range []int{8, 9} {
		select {
		case got := <-replies:
			if got != want {
				t.Fatalf("ACK %d; want %d", got, want)
			}
		case <-time.After(time.Second):
			t.Fatal("lost control ACK")
		}
	}
}
