package api

import (
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/wsyzxjn/uulink/pkg/auth"
)

func TestLiveGuestQRCodeAbstract(t *testing.T) {
	if os.Getenv("UULINK_LIVE") == "" {
		t.Skip("set UULINK_LIVE=1 to run live tests")
	}

	cfg, err := auth.LoadConfigFile("../../config.json")
	if err != nil {
		t.Skipf("config.json not available: %v", err)
	}
	client := NewClient(cfg)
	guest, err := client.CreateGuest()
	if err != nil {
		t.Fatalf("create guest: %v", err)
	}
	if _, err := client.CreateGuestRoom(guest); err != nil {
		t.Fatalf("create guest room: %v", err)
	}
	share, err := client.GetGuestShareInfo(guest)
	if err != nil {
		t.Fatalf("get guest share info: %v", err)
	}

	querySets := []map[string]string{
		{"device_id": guest.DeviceID},
		{"guest_id": guest.GuestID},
		{"user_id": guest.UserID},
		{"connect_id": share.ConnectID},
		{"control_id": cfg.DeviceID},
		{"type": "guest"},
		{"device_id": guest.DeviceID, "guest_id": guest.GuestID},
		{"device_id": guest.DeviceID, "connect_id": share.ConnectID},
		{"guest_id": guest.GuestID, "connect_id": share.ConnectID},
		{"device_id": guest.DeviceID, "user_id": guest.UserID},
		{"device_id": guest.DeviceID, "control_id": cfg.DeviceID},
		{"connect_id": share.ConnectID, "control_id": cfg.DeviceID},
		{"device_id": guest.DeviceID, "type": "guest"},
		{"connect_id": share.ConnectID, "type": "guest"},
		{"device_id": guest.DeviceID, "guest_id": guest.GuestID, "connect_id": share.ConnectID},
	}
	for _, query := range querySets {
		values := url.Values{}
		for key, value := range query {
			values.Set(key, value)
		}
		path := "/api/v1/guest/qrcode/abstract?" + values.Encode()
		resp, err := client.guestClient(guest).Do("GET", path, nil)
		if err != nil {
			t.Fatalf("guest qrcode abstract %s: %v", strings.Join(sortedKeys(query), ","), err)
		}
		code, _ := resp["code"].(float64)
		message, _ := resp["msg"].(string)
		data, _ := resp["data"].(map[string]any)
		t.Logf("query=%s code=%v msg=%q data_keys=%v",
			strings.Join(sortedKeys(query), ","), code, message, mapKeys(data))
		for key, value := range data {
			if text, ok := value.(string); ok {
				t.Logf("query=%s field=%s length=%d",
					strings.Join(sortedKeys(query), ","), key, len(text))
				continue
			}
			t.Logf("query=%s field=%s type=%T",
				strings.Join(sortedKeys(query), ","), key, value)
		}
	}
}

func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}
