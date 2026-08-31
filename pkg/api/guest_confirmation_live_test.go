package api

import (
	"os"
	"testing"

	"github.com/user/uulink/pkg/auth"
)

func TestLiveGuestConfirmationJoin(t *testing.T) {
	if os.Getenv("UULINK_LIVE") == "" {
		t.Skip("set UULINK_LIVE=1 to run live tests")
	}

	cfg, err := auth.LoadConfigFile("../../config.json")
	if err != nil {
		t.Skipf("config.json not available: %v", err)
	}

	client := NewClient(cfg)
	guestCfg := *cfg
	guestCfg.JWT = ""
	guestCfg.UserID = ""
	guestCfg.GuestID = ""
	guestCfg.ClientID = os.Getenv("UULINK_GUEST_CLIENT_ID")
	if guestCfg.ClientID == "" {
		guestCfg.ClientID = cfg.ClientID
	}
	guestCfg.DeviceID = os.Getenv("UULINK_GUEST_DEVICE_ID")
	if guestCfg.DeviceID == "" {
		guestCfg.DeviceID = cfg.DeviceID
	}
	guestClient := NewClient(&guestCfg)

	guest, err := guestClient.CreateGuest()
	if err != nil {
		t.Fatalf("create guest: %v", err)
	}
	if _, err := guestClient.CreateGuestRoom(guest); err != nil {
		t.Fatalf("create guest room: %v", err)
	}
	share, err := guestClient.GetGuestShareInfo(guest)
	if err != nil {
		t.Fatalf("get guest share info: %v", err)
	}
	if share.ConnectID == "" {
		t.Fatal("guest share info has no connect_id")
	}

	room, err := client.JoinRoomByConfirmation(share.ConnectID, cfg.DeviceID)
	if err != nil {
		responseErr, ok := err.(*ResponseError)
		if !ok {
			t.Fatalf("join by confirmation: %v", err)
		}
		data, _ := responseErr.Response["data"].(map[string]any)
		t.Logf("join by confirmation returned code=%d msg=%q data_keys=%v",
			responseErr.Code, responseErr.Message, mapKeys(data))
		return
	}

	t.Logf("join by confirmation succeeded: token_length=%d gateway_count=%d",
		len(room.Token), len(room.SignalingList))
}
