package api

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/user/uulink/pkg/auth"
)

// TestLiveRoomCreate tries POST /api/v1/room/create to see the room creation
// flow from the server (controlled) side. Skipped unless UULINK_LIVE=1 is set.
func TestLiveRoomCreate(t *testing.T) {
	if os.Getenv("UULINK_LIVE") == "" {
		t.Skip("set UULINK_LIVE=1 to run live test")
	}

	cfg, err := auth.LoadConfigFile("../../config.json")
	if err != nil {
		t.Skip("config.json not found:", err)
	}

	client := NewClient(cfg)

	resp, err := client.Do("POST", "/api/v1/room/create", map[string]any{})
	if err != nil {
		t.Fatalf("room create: %v", err)
	}

	redacted := redactRoomCreateResponse(resp)
	pretty, _ := json.MarshalIndent(redacted, "", "  ")
	t.Logf("room create response:\n%s", pretty)
}

func redactRoomCreateResponse(resp map[string]any) map[string]any {
	out := make(map[string]any, len(resp))
	for key, value := range resp {
		out[key] = value
	}
	data, ok := out["data"].(map[string]any)
	if !ok {
		return out
	}
	redactedData := make(map[string]any, len(data))
	for key, value := range data {
		redactedData[key] = value
	}
	for _, key := range []string{"token", "report_token", "nrd_auth", "auth"} {
		if _, exists := redactedData[key]; exists {
			redactedData[key] = "<redacted>"
		}
	}
	out["data"] = redactedData
	return out
}
