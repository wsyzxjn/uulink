package signaling

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestGatewaySTUNParsing(t *testing.T) {
	data := json.RawMessage(`[
		{"urls":"stun:one.example:3478"},
		{"urls":["stun:one.example:3478","stuns:two.example:5349","turn:relay.example:3478"],"username":"not-retained","credential":"not-retained"},
		{"urls":22}, {"urls":"https://not-stun.example"}, {"urls":"stun:"},
		{"urls":"stun:three.example:3479"}
	]`)
	want := []string{"stun:one.example:3478", "stuns:two.example:5349", "stun:three.example:3479"}
	if got := stunServersFromJSON(data); !reflect.DeepEqual(got, want) {
		t.Fatalf("URLs=%v, want %v", got, want)
	}
	for _, data := range []string{"null", "{}", `[{"urls":"turn:relay.example:3478"}]`, "invalid"} {
		if got := stunServersFromJSON(json.RawMessage(data)); len(got) != 0 {
			t.Fatalf("unexpected STUN list from %s", data)
		}
	}
}

func TestControlledInfoEnvelope(t *testing.T) {
	for _, raw := range []string{
		`{"client_id":"controller","ice_id":"ice","app_control_id":"app","iceServers":[{"urls":"stun:example.com:3478"}]}`,
		`{"client_id":"controller","data":{"ice_id":"ice","app_control_id":"app","iceServers":[{"urls":["stun:example.com:3478"]}]}}`,
	} {
		info, err := ParseControlledInfo(&Event{Args: []json.RawMessage{json.RawMessage(raw)}})
		if err != nil {
			t.Fatal(err)
		}
		if info.ClientID != "controller" || info.IceID != "ice" || info.AppControlID != "app" || len(info.STUNServers) != 1 {
			t.Fatalf("wrong metadata: %+v", info)
		}
	}
	if _, err := ParseControlledInfo(&Event{}); err == nil {
		t.Fatal("accepted missing event arguments")
	}
}
