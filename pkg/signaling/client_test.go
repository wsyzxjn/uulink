package signaling

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestClientCloseIsConcurrentSafe(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		if err := conn.WriteMessage(websocket.TextMessage, []byte(`0{"sid":"test","pingInterval":60000,"pingTimeout":60000}`)); err != nil {
			return
		}
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer server.Close()

	gateway := "ws" + strings.TrimPrefix(server.URL, "http")
	client, err := Connect(&ConnectConfig{GatewayURL: gateway})
	if err != nil {
		t.Fatalf("Connect(): %v", err)
	}

	var wait sync.WaitGroup
	for range 32 {
		wait.Go(func() {
			_ = client.Close()
		})
	}
	wait.Wait()
	select {
	case <-client.Done():
	default:
		t.Fatal("Done() was not closed")
	}
}

// A gateway that goes silent must be detected through the read deadline
// derived from its advertised ping timings, not left to OS keepalives.
func TestClientDetectsSilentGateway(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		// Tiny timings, then never answer anything (not even pings).
		if err := conn.WriteMessage(websocket.TextMessage, []byte(`0{"sid":"test","pingInterval":100,"pingTimeout":100}`)); err != nil {
			return
		}
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer server.Close()

	gateway := "ws" + strings.TrimPrefix(server.URL, "http")
	client, err := Connect(&ConnectConfig{GatewayURL: gateway})
	if err != nil {
		t.Fatalf("Connect(): %v", err)
	}
	defer client.Close()

	select {
	case <-client.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("client did not notice the silent gateway")
	}
}
