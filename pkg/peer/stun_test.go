package peer

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/wsyzxjn/uulink/pkg/settings"
	"github.com/wsyzxjn/uulink/pkg/signaling"
)

func TestControlledSTUNSelection(t *testing.T) {
	offer := soacEvent{ClientID: "controller"}
	offer.Data.IceID, offer.Data.AppControlID = "ice", "app"
	p := &Peer{network: settings.Defaults(), roomSTUNServers: []string{"stun:room.example:3478"}}
	check := func(source string, want []string) {
		t.Helper()
		got, actual := p.controlledSTUNServers(offer)
		if actual != source || !reflect.DeepEqual(got, want) {
			t.Fatalf("source=%s urls=%v, want %s %v", actual, got, source, want)
		}
	}
	check("room_info", p.roomSTUNServers)
	p.handleControlledInfo(&signaling.Event{Args: []json.RawMessage{json.RawMessage(`{"client_id":"controller","ice_id":"ice","app_control_id":"app","iceServers":[{"urls":"stun:fresh.example:3478"}]}`)}})
	check("be-controlled", []string{"stun:fresh.example:3478"})
	p.controlledInfo.IceID = "previous-ice"
	check("room_info", p.roomSTUNServers)
	p.controlledInfo.IceID = "ice"
	p.controlledInfo.ClientID = "another-controller"
	check("room_info", p.roomSTUNServers)
	p.controlledInfo.ClientID = "controller"
	p.controlledInfo.AppControlID = "previous-app"
	check("room_info", p.roomSTUNServers)
	p.controlledInfo.AppControlID = "app"
	p.network.STUNServers = []string{"stun:custom.example:3478"}
	check("config", p.network.STUNServers)
	p.network.STUNServers = []string{}
	check("config", []string{})
	p.network.STUNServers = nil
	p.handleControlledInfo(&signaling.Event{Args: []json.RawMessage{json.RawMessage(`{"iceServers":[]}`)}})
	check("room_info", p.roomSTUNServers)
	p.roomSTUNServers = nil
	check("fallback", settings.DefaultSTUNServers())
	if p.network.STUNServers != nil {
		t.Fatal("fallback changed the automatic setting")
	}
}

func TestControlledSTUNRefreshAndMalformedEvent(t *testing.T) {
	p := &Peer{network: settings.Defaults()}
	for _, host := range []string{"old.example", "new.example"} {
		raw, _ := json.Marshal(map[string]any{"iceServers": []any{map[string]string{"urls": "stun:" + host + ":3478"}}})
		p.handleControlledInfo(&signaling.Event{Args: []json.RawMessage{raw}})
		urls, source := p.controlledSTUNServers(soacEvent{})
		if source != "be-controlled" || urls[0] != "stun:"+host+":3478" {
			t.Fatal("gateway update was ignored")
		}
	}
	p.handleControlledInfo(&signaling.Event{Args: []json.RawMessage{json.RawMessage(`{"iceServers":`)}})
	if _, source := p.controlledSTUNServers(soacEvent{}); source != "fallback" {
		t.Fatal("stale metadata survived malformed replacement")
	}
}
