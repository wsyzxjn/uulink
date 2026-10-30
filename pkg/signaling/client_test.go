//go:build integration

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

// EIO=4 heartbeats run from the gateway: the client answers each ping with a
// pong and never sends its own ping, like the official client.
func TestClientOnlyAnswersGatewayPings(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	received := make(chan string, 64)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		// A short interval gives an old client-side ping loop several chances
		// to fire during the test.
		if err := conn.WriteMessage(websocket.TextMessage, []byte(`0{"sid":"test","pingInterval":40,"pingTimeout":1000}`)); err != nil {
			return
		}
		go func() {
			for range 3 {
				time.Sleep(60 * time.Millisecond)
				if conn.WriteMessage(websocket.TextMessage, []byte("2")) != nil {
					return
				}
			}
		}()
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}
			received <- string(msg)
		}
	}))
	defer server.Close()

	gateway := "ws" + strings.TrimPrefix(server.URL, "http")
	client, err := Connect(&ConnectConfig{GatewayURL: gateway})
	if err != nil {
		t.Fatalf("Connect(): %v", err)
	}
	defer client.Close()

	pongs := 0
	deadline := time.After(400 * time.Millisecond)
	for {
		select {
		case msg := <-received:
			switch msg {
			case "2":
				t.Fatal("client sent an engine.io ping; EIO=4 clients only answer the gateway's pings")
			case "3":
				pongs++
			}
		case <-deadline:
			if pongs != 3 {
				t.Fatalf("client answered %d of 3 gateway pings", pongs)
			}
			return
		}
	}
}

func TestClientNamespaceDisconnectedOnSIODisconnect(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.WriteMessage(websocket.TextMessage, []byte(`0{"sid":"test","pingInterval":25000,"pingTimeout":20000}`))
		time.Sleep(50 * time.Millisecond)
		_ = conn.WriteMessage(websocket.TextMessage, []byte(`40{"sid":"test"}`))
		time.Sleep(50 * time.Millisecond)
		_ = conn.WriteMessage(websocket.TextMessage, []byte("41"))
		time.Sleep(500 * time.Millisecond)
	}))
	defer server.Close()

	gateway := "ws" + strings.TrimPrefix(server.URL, "http")
	client, err := Connect(&ConnectConfig{GatewayURL: gateway})
	if err != nil {
		t.Fatalf("Connect(): %v", err)
	}
	defer client.Close()

	select {
	case <-client.NamespaceDisconnected():
	case <-time.After(2 * time.Second):
		t.Fatal("NamespaceDisconnected was not closed on sioDisconnect")
	}

	select {
	case <-client.Done():
		t.Fatal("client.Done() was closed; expected only namespace to disconnect")
	default:
	}
}
