package peer

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/wsyzxjn/uulink/pkg/signaling"
)

func TestControlledOfferFailureLeavesPeerReadyForNextOffer(t *testing.T) {
	p := &Peer{controlledReady: make(chan struct{}), statsDone: make(chan struct{})}
	close(p.controlledReady)

	emptyOffer, err := json.Marshal(map[string]any{
		"client_id": "controller-1",
		"data":      map[string]any{"type": "offer", "sdp": "", "app_control_id": "ac-1", "ice_id": "ice-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	p.handleControlledSOAC(&signaling.Event{Name: "soac", Args: []json.RawMessage{emptyOffer}})

	p.mu.Lock()
	pc := p.pc
	p.mu.Unlock()
	if pc != nil {
		t.Fatal("failed offer left a PeerConnection behind; later offers would be dropped as duplicates")
	}

	// A failed offer must not poison the connection with a stale, never-applied
	// remote description or with candidates that belonged to it.
	p.mu.Lock()
	remoteDescSet, pendingCandidates := p.remoteDescSet, len(p.pendingCandidates)
	p.mu.Unlock()
	if remoteDescSet || pendingCandidates != 0 {
		t.Fatalf("stale state after failed offer: remoteDescSet=%v pending=%d", remoteDescSet, pendingCandidates)
	}

	// An offer that is rejected before validation must not adopt the sender's
	// routing identity; that only happens once a valid offer is answered.
	if p.routingClientID != "" || p.appControlID != "" {
		t.Fatalf("invalid offer changed identity: routing=%q app_control=%q", p.routingClientID, p.appControlID)
	}
}

func TestReplacePBBytesFieldUpdatesControlDeviceAndCapability(t *testing.T) {
	pb, err := hex.DecodeString(ConnectOptionsHex)
	if err != nil {
		t.Fatal(err)
	}

	updated, err := replacePBBytesField(pb, 9, []byte("test-device-123456"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(updated, []byte("test-device-123456")) {
		t.Fatal("control device ID was not replaced")
	}
	if bytes.Contains(updated, []byte("aeawqa5txeafoxl4")) {
		t.Fatal("captured control device ID remained in ConnectOptions")
	}

	capability := mustHex("08061003180320022801300238024003480150015801")
	updated, err = replacePBBytesField(updated, 11, capability)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(updated, capability) {
		t.Fatal("capability field was not replaced")
	}

	updated, err = replacePBBytesField(updated, 12, []byte("4.39.0"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(updated, []byte("4.39.0")) {
		t.Fatal("version name field was not replaced")
	}
	if bytes.Contains(updated, []byte("4.38.0")) {
		t.Fatal("default version name remained in ConnectOptions")
	}
}

func TestParseControlEchoUsesOuterMessageSeqAndRemoteFeatureFlags(t *testing.T) {
	inner := appendPBVarintField(nil, 1, 1)
	inner = appendPBBytesField(inner, 2, []byte(`{"seq":99}`))
	remoteFeatureFlags := mustHex("08061003180320022801300238024003480150015801")
	inner = appendPBBytesField(inner, 4, remoteFeatureFlags)

	frame := appendPBVarintField(nil, 1, 287)
	frame = appendPBVarintField(frame, 2, 1788020417755)
	frame = appendPBBytesField(frame, 3, inner)

	seq, featureFlags, ok := parseControlEcho(frame)
	if !ok {
		t.Fatal("expected handshake frame to parse")
	}
	if seq != 287 {
		t.Fatalf("seq = %d, want outer message seq 287", seq)
	}
	if string(featureFlags) != string(remoteFeatureFlags) {
		t.Fatalf("feature flags = %x, want remote feature flags %x", featureFlags, remoteFeatureFlags)
	}
}
