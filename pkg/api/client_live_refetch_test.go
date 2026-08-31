package api

import (
	"os"
	"testing"
	"time"

	"github.com/user/uulink/pkg/auth"
	"github.com/user/uulink/pkg/signaling"
)

func TestLiveRoomJoinRefetch(t *testing.T) {
	if os.Getenv("UULINK_LIVE") == "" {
		t.Skip("set UULINK_LIVE=1 to run live test")
	}

	cfg, err := auth.LoadConfigFile("../../config.json")
	if err != nil {
		t.Skip("config.json not found:", err)
	}
	client := NewClient(cfg)

	room, err := client.CreateRoom()
	if err != nil {
		t.Fatalf("create room: %v", err)
	}

	sig, err := signaling.Connect(&signaling.ConnectConfig{
		GatewayURL:  room.SignalingServer,
		NRDAuth:     room.Token,
		Controlling: false,
	})
	if err != nil {
		t.Fatalf("connect signaling: %v", err)
	}
	defer sig.Close()

	select {
	case <-sig.NamespaceConnected():
	case <-time.After(5 * time.Second):
		t.Fatal("signaling namespace connect timeout")
	case <-sig.Done():
		t.Fatal("signaling closed")
	}

	info, err := sig.RequestRoomInfo()
	if err != nil {
		t.Fatalf("room info: %v", err)
	}
	t.Logf("active room_id=%s controlled_client_id=%s device_id=%s", info.RoomID, info.ClientID, info.DeviceID)

	reconnectKey, err := sig.RefreshReconnectKey()
	if err != nil {
		t.Fatalf("refresh reconnect key: %v", err)
	}

	refetched, err := client.RefetchRoomJoin(reconnectKey)
	if err != nil {
		t.Fatalf("refetch room join with reconnect key: %v", err)
	}
	t.Logf(
		"refetch succeeded: room_id_present=%v token_length=%d gateway_count=%d report_url_present=%v",
		refetched.RoomID != "",
		len(refetched.Token),
		len(refetched.SignalingList),
		refetched.ReportURL != "",
	)
}
