package peer

import (
	"bytes"
	"encoding/hex"
	"testing"
)

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
