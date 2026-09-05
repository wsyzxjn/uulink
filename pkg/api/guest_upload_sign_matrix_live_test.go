package api

import (
	"errors"
	"os"
	"testing"

	"github.com/wsyzxjn/uulink/pkg/auth"
)

func TestLiveGuestShareUploadSignMatrix(t *testing.T) {
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
	controlledShare, err := controlledClient.GetGuestShareInfo(controlledGuest)
	if err != nil {
		t.Fatalf("get controlled share info: %v", err)
	}
	controllerShare, err := controllerClient.GetGuestShareInfo(controllerGuest)
	if err != nil {
		t.Fatalf("get controller share info: %v", err)
	}

	passCode, err := GenerateSharePassCode()
	if err != nil {
		t.Fatalf("generate pass code: %v", err)
	}
	candidates := map[string]string{
		"controller_guest_id":  controllerGuest.GuestID,
		"controller_device_id": controllerGuest.DeviceID,
		"controller_user_id":   controllerGuest.UserID,
		"controller_connect":   controllerShare.ConnectID,
		"controller_client_id": controllerClient.cfg.ClientID,
		"controlled_connect":   controlledShare.ConnectID,
		"config_device_id":     cfg.DeviceID,
		"config_client_id":     cfg.ClientID,
	}
	for name, controlID := range candidates {
		signs := map[string]string{
			"no_salt":   SharePassCodeSign(passCode),
			"with_salt": SharePassCodeSignWithSalt(controlID, passCode),
		}
		for signName, sign := range signs {
			request := NewGuestShareUploadSignRequest(controlID, passCode, "", ShareAuthTemporary)
			request.Sign = sign
			resp, err := controlledClient.GuestShareUploadSign(controlledGuest, request)
			if err != nil {
				var responseErr *ResponseError
				if !errors.As(err, &responseErr) {
					t.Fatalf("upload sign %s/%s: %v", name, signName, err)
				}
				data, _ := responseErr.Response["data"].(map[string]any)
				t.Logf("candidate=%s sign=%s code=%d msg=%q data_keys=%v",
					name, signName, responseErr.Code, responseErr.Message, mapKeys(data))
				continue
			}
			t.Logf("candidate=%s sign=%s succeeded keys=%v",
				name, signName, mapKeys(resp))
			data, _ := resp["data"].(map[string]any)
			for key, value := range data {
				if text, ok := value.(string); ok {
					t.Logf("candidate=%s sign=%s field=%s length=%d",
						name, signName, key, len(text))
					continue
				}
				t.Logf("candidate=%s sign=%s field=%s type=%T",
					name, signName, key, value)
			}
		}
	}
}
