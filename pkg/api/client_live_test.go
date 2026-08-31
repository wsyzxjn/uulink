package api

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/user/uulink/pkg/auth"
)

// TestLiveRoomJoin tests the room join API against the live server.
// Requires config.json in the project root with valid credentials.
// Skipped unless UULINK_LIVE=1 is set.
func TestLiveRoomJoin(t *testing.T) {
	if os.Getenv("UULINK_LIVE") == "" {
		t.Skip("set UULINK_LIVE=1 to run live test")
	}

	data, err := os.ReadFile("../../config.json")
	if err != nil {
		t.Skip("config.json not found, skipping live test")
	}

	var cfg auth.Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse config: %v", err)
	}

	client := NewClient(&cfg)

	// Get user info first to verify auth works
	userInfo, err := client.GetUserInfo()
	if err != nil {
		t.Fatalf("get user info: %v", err)
	}
	t.Logf("user info: %v", userInfo)

	// Try joining a room for the Windows device (may be offline)
	resp, err := client.JoinRoom("aeawn7l56uabjgfc", false)
	if err != nil {
		t.Logf("join room error (expected if device offline): %v", err)
		return
	}

	// Dump the full response structure
	pretty, _ := json.MarshalIndent(resp, "", "  ")
	t.Logf("room join response:\n%s", pretty)

	// Check business error code
	if code, ok := resp["code"].(float64); ok && code != 0 {
		t.Logf("business error code %v: %v (expected if device offline)", code, resp["msg"])
		return
	}

	room, err := ParseRoomJoin(resp)
	if err != nil {
		t.Fatalf("parse room join: %v", err)
	}
	authPreview := room.NRDAuth
	if len(authPreview) > 20 {
		authPreview = authPreview[:20] + "..."
	}
	t.Logf("parsed: roomID=%q nrdAuth=%q gateways=%v", room.RoomID, authPreview, room.Gateways)
}
