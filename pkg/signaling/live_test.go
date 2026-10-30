package signaling

import (
	"os"
	"testing"
	"time"

	"github.com/wsyzxjn/uulink/pkg/api"
	"github.com/wsyzxjn/uulink/pkg/auth"
)

// TestLiveSignalingConnect creates a room and connects to the signaling
// gateway with the returned token. Verifies the WebSocket + EIO=4 + socket.io
// handshake works end to end.
//
// Run with: go test ./pkg/signaling/ -run TestLiveSignalingConnect -tags live
// Note: the gateway rate-limits room creation — don't run repeatedly.
func TestLiveSignalingConnect(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live test in short mode")
	}
	if os.Getenv("UULINK_LIVE") == "" {
		t.Skip("set UULINK_LIVE=1 to run live signaling test")
	}

	cfg, err := auth.LoadConfigFile("../../config.json")
	if err != nil {
		t.Skip("config.json not found:", err)
	}

	client := api.NewClient(cfg)
	room, err := client.CreateRoom()
	if err != nil {
		t.Fatalf("create room: %v", err)
	}
	t.Logf("room created, signaling_server=%s", room.SignalingServer)

	if room.Token == "" {
		t.Fatal("no token in room create response")
	}

	sig, err := Connect(&ConnectConfig{
		GatewayURL:  room.SignalingServer,
		NRDAuth:     room.Token,
		Controlling: false, // we are the room creator = server side
	})
	if err != nil {
		t.Fatalf("signaling connect: %v", err)
	}
	defer sig.Close()

	// Collect events for 8 seconds
	events := make(chan string, 32)
	sig.On("bmsg_push", func(ev *Event) {
		if len(ev.Args) > 0 {
			events <- "bmsg_push: " + string(ev.Args[0])
		}
	})

	timeout := time.After(8 * time.Second)
	for {
		select {
		case ev := <-events:
			t.Logf("event: %s", ev)
		case <-timeout:
			t.Log("collection window elapsed")
			return
		case <-sig.Done():
			t.Fatal("signaling connection closed prematurely")
		}
	}
}

// TestLiveGatewayHeartbeat keeps a signaling connection open past one full
// liveness window without sending engine.io pings of its own. Surviving it
// shows that the gateway pings (otherwise the read deadline would expire) and
// accepts pong-only clients (otherwise it would close the connection).
//
// Run with: UULINK_LIVE=1 go test ./pkg/signaling/ -run TestLiveGatewayHeartbeat -v
func TestLiveGatewayHeartbeat(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live test in short mode")
	}
	if os.Getenv("UULINK_LIVE") == "" {
		t.Skip("set UULINK_LIVE=1 to run live signaling test")
	}

	cfg, err := auth.LoadConfigFile("../../config.json")
	if err != nil {
		t.Skip("config.json not found:", err)
	}
	room, err := api.NewClient(cfg).CreateRoom()
	if err != nil {
		t.Fatalf("create room: %v", err)
	}
	sig, err := Connect(&ConnectConfig{
		GatewayURL:  room.SignalingServer,
		NRDAuth:     room.Token,
		Controlling: false,
		Network:     cfg.Network,
		Version:     cfg.Identity().StreamerVersion,
		UserAgent:   cfg.Identity().WebSocketUserAgent,
	})
	if err != nil {
		t.Fatalf("signaling connect: %v", err)
	}
	defer sig.Close()

	window := sig.pingInterval + sig.pingTimeout
	hold := window + sig.pingInterval
	t.Logf("gateway pingInterval=%s pingTimeout=%s; holding %s", sig.pingInterval, sig.pingTimeout, hold)
	select {
	case <-sig.Done():
		t.Fatal("signaling connection closed within the liveness window")
	case <-time.After(hold):
		t.Logf("connection alive after %s without client pings", hold)
	}
}
