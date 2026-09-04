package peer

import (
	"testing"

	"github.com/pion/webrtc/v4"
)

func TestParseTransportMode(t *testing.T) {
	for _, tt := range []struct {
		value string
		want  TransportMode
	}{
		{"auto", TransportAuto},
		{"relay", TransportRelay},
	} {
		got, err := ParseTransportMode(tt.value)
		if err != nil {
			t.Fatalf("ParseTransportMode(%q): %v", tt.value, err)
		}
		if got != tt.want {
			t.Fatalf("ParseTransportMode(%q) = %q, want %q", tt.value, got, tt.want)
		}
	}

	if _, err := ParseTransportMode("direct"); err == nil {
		t.Fatal("ParseTransportMode accepted unsupported mode")
	}
}

func TestResolveTransportModeServerRequirementWins(t *testing.T) {
	if got := resolveTransportMode("", false); got != TransportAuto {
		t.Fatalf("zero mode resolved to %q, want auto", got)
	}
	if got := resolveTransportMode(TransportAuto, true); got != TransportRelay {
		t.Fatalf("server requirement resolved to %q, want relay", got)
	}
	if got := resolveTransportMode(TransportRelay, false); got != TransportRelay {
		t.Fatalf("local relay resolved to %q, want relay", got)
	}
}

func TestHasTURNServer(t *testing.T) {
	if hasTURNServer([]webrtc.ICEServer{{URLs: []string{"stun:61.174.14.99:2580"}}}) {
		t.Fatal("STUN-only servers reported as TURN")
	}
	if !hasTURNServer([]webrtc.ICEServer{{URLs: []string{"turn:relay.example:3478"}}}) {
		t.Fatal("TURN server not detected")
	}
	if !hasTURNServer([]webrtc.ICEServer{{URLs: []string{"TURNS:relay.example:5349"}}}) {
		t.Fatal("TURNS server not detected case-insensitively")
	}
}

func TestTransportICEPolicy(t *testing.T) {
	if got := transportICEPolicy(TransportAuto); got != webrtc.ICETransportPolicyAll {
		t.Fatalf("auto policy = %v, want all", got)
	}
	if got := transportICEPolicy(TransportRelay); got != webrtc.ICETransportPolicyRelay {
		t.Fatalf("relay policy = %v, want relay", got)
	}
}

func TestConnectRelayRequiresTURNServer(t *testing.T) {
	p := &Peer{
		transportMode: TransportRelay,
		ack:           &ControlAckData{ICEServers: nil},
	}
	if err := p.Connect(nil); err == nil {
		t.Fatal("relay connect accepted an ack without TURN servers")
	}

	p = &Peer{
		transportMode: TransportAuto,
		ack:           &ControlAckData{ForceRelay: true, ICEServers: nil},
	}
	if err := p.Connect(nil); err == nil {
		t.Fatal("server-required relay accepted an ack without TURN servers")
	}
}

func TestConnectRejectsUnknownTransportMode(t *testing.T) {
	p := &Peer{
		transportMode: "direct",
		ack:           &ControlAckData{ICEServers: nil},
	}
	if err := p.Connect(nil); err == nil {
		t.Fatal("connect accepted an unknown transport mode")
	}
}

func TestValidateTransportModeRequiresSelectedRelayPair(t *testing.T) {
	p := &Peer{effectiveTransportMode: TransportRelay}
	if err := p.ValidateTransportMode(); err == nil {
		t.Fatal("relay validation accepted a nil selected pair")
	}

	p.selectedPair = &webrtc.ICECandidatePair{
		Local:  &webrtc.ICECandidate{Typ: webrtc.ICECandidateTypeRelay},
		Remote: &webrtc.ICECandidate{Typ: webrtc.ICECandidateTypeSrflx},
	}
	if err := p.ValidateTransportMode(); err != nil {
		t.Fatalf("relay pair rejected: %v", err)
	}

	p.selectedPair = &webrtc.ICECandidatePair{
		Local:  &webrtc.ICECandidate{Typ: webrtc.ICECandidateTypeHost},
		Remote: &webrtc.ICECandidate{Typ: webrtc.ICECandidateTypeSrflx},
	}
	if err := p.ValidateTransportMode(); err == nil {
		t.Fatal("relay validation accepted a direct pair")
	}
}
