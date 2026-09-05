package api

import (
	"errors"
	"os"
	"testing"

	"github.com/wsyzxjn/uulink/pkg/auth"
)

func guestConfigFromEnv(cfg *auth.Config, prefix string) *auth.Config {
	out := *cfg
	out.JWT = ""
	out.UserID = ""
	out.GuestID = ""
	if value := os.Getenv(prefix + "_CLIENT_ID"); value != "" {
		out.ClientID = value
	}
	if value := os.Getenv(prefix + "_DEVICE_ID"); value != "" {
		out.DeviceID = value
	}
	return &out
}

func TestLiveGuestToGuestConfirmationJoin(t *testing.T) {
	if os.Getenv("UULINK_LIVE") == "" {
		t.Skip("set UULINK_LIVE=1 to run live tests")
	}

	cfg, err := auth.LoadConfigFile("../../config.json")
	if err != nil {
		t.Skipf("config.json not available: %v", err)
	}
	controlledClient := NewClient(guestConfigFromEnv(cfg, "UULINK_GUEST_A"))
	controllerClient := NewClient(guestConfigFromEnv(cfg, "UULINK_GUEST_B"))

	controlledGuest, err := controlledClient.CreateGuest()
	if err != nil {
		t.Fatalf("create controlled guest: %v", err)
	}
	controllerGuest, err := controllerClient.CreateGuest()
	if err != nil {
		t.Fatalf("create controller guest: %v", err)
	}
	if _, err := controlledClient.CreateGuestRoom(controlledGuest); err != nil {
		t.Fatalf("create controlled guest room: %v", err)
	}
	if _, err := controllerClient.CreateGuestRoom(controllerGuest); err != nil {
		t.Fatalf("create controller guest room: %v", err)
	}
	share, err := controlledClient.GetGuestShareInfo(controlledGuest)
	if err != nil {
		t.Fatalf("get controlled guest share info: %v", err)
	}
	controllerShare, err := controllerClient.GetGuestShareInfo(controllerGuest)
	if err != nil {
		t.Fatalf("get controller guest share info: %v", err)
	}
	if share.ConnectID == "" {
		t.Fatal("controlled guest share info has no connect_id")
	}
	if controllerShare.ConnectID == "" {
		t.Fatal("controller guest share info has no connect_id")
	}

	passCode, err := GenerateSharePassCode()
	if err != nil {
		t.Fatalf("generate share pass code: %v", err)
	}
	sign := SharePassCodeSign(passCode)
	uploadResp, uploadErr := controlledClient.GuestShareUploadSign(controlledGuest, &GuestShareUploadSignRequest{
		CanControl:       true,
		ControlID:        controllerShare.ConnectID,
		Sign:             sign,
		BackupSign:       sign,
		ControlMode:      "by_confirmation",
		NeedConfirmation: true,
	})
	if uploadErr != nil {
		var responseErr *ResponseError
		if !errors.As(uploadErr, &responseErr) {
			t.Fatalf("guest share upload sign: %v", uploadErr)
		}
		data, _ := responseErr.Response["data"].(map[string]any)
		t.Logf("guest share upload sign returned code=%d msg=%q data_keys=%v",
			responseErr.Code, responseErr.Message, mapKeys(data))
	} else {
		t.Logf("guest share upload sign succeeded: keys=%v", mapKeys(uploadResp))
	}

	room, err := controllerClient.JoinRoomByConfirmationWithGuest(
		controllerGuest, share.ConnectID, share.ConnectCode)
	if err != nil {
		var responseErr *ResponseError
		if !errors.As(err, &responseErr) {
			t.Fatalf("guest join by confirmation: %v", err)
		}
		data, _ := responseErr.Response["data"].(map[string]any)
		t.Logf("guest join by confirmation returned code=%d msg=%q data_keys=%v",
			responseErr.Code, responseErr.Message, mapKeys(data))
		return
	}

	t.Logf("guest join by confirmation succeeded: token_length=%d gateway_count=%d",
		len(room.Token), len(room.SignalingList))
}
