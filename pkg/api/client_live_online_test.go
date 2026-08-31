package api

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/user/uulink/pkg/auth"
)

// TestLiveRoomJoinOnline joins the local Mac (QmQ, always online as this
// machine's own device) to capture the successful room join response format.
// Skipped unless UULINK_LIVE=1 is set.
func TestLiveRoomJoinOnline(t *testing.T) {
	if os.Getenv("UULINK_LIVE") == "" {
		t.Skip("set UULINK_LIVE=1 to run live test")
	}

	cfg, err := auth.LoadConfigFile("../../config.json")
	if err != nil {
		t.Skip("config.json not found:", err)
	}

	client := NewClient(cfg)

	resp, err := client.JoinRoom(cfg.DeviceID, false)
	if err != nil {
		t.Fatalf("join room: %v", err)
	}

	pretty, _ := json.MarshalIndent(resp, "", "  ")
	t.Logf("room join response:\n%s", pretty)

	if code, ok := resp["code"].(float64); ok && code != 0 {
		t.Logf("business error code %v: %v", code, resp["msg"])
		return
	}
}
