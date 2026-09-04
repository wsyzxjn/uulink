package gvpb

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"
)

// TestConnectRoundTrip verifies protobuf encode/decode of a CONNECT frame.
func TestConnectRoundTrip(t *testing.T) {
	m := &Message{
		Seq:       "6",
		Timestamp: "1788020351",
		PortMappingFrame: &PortMappingFrame{
			SessionID: "1",
			RuleID:    "1788015422013002",
			StreamID:  "1",
			Type:      TypeConnect,
			Payload:   NewConnect("127.0.0.1", 3389),
		},
	}
	enc, err := m.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(enc) == 0 {
		t.Fatal("empty encoding")
	}

	dec, err := DecodeMessage(enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if dec.Seq != "6" || dec.Timestamp != "1788020351" {
		t.Errorf("seq/timestamp mismatch: %q %q", dec.Seq, dec.Timestamp)
	}
	f := dec.PortMappingFrame
	if f == nil {
		t.Fatal("frame missing")
	}
	if f.SessionID != "1" || f.RuleID != "1788015422013002" || f.StreamID != "1" {
		t.Errorf("frame fields mismatch: %+v", f)
	}
	if f.Type != TypeConnect {
		t.Errorf("type = %q, want empty", f.Type)
	}
	var target struct {
		Version    int    `json:"version"`
		TargetPort int    `json:"target_port"`
		TargetHost string `json:"target_host"`
	}
	if err := json.Unmarshal(f.Payload, &target); err != nil {
		t.Fatalf("payload json: %v", err)
	}
	if target.Version != 1 || target.TargetPort != 3389 || target.TargetHost != "127.0.0.1" {
		t.Errorf("payload mismatch: %+v", target)
	}
}

// TestSynAckRoundTrip verifies SYN_ACK decode.
func TestSynAckRoundTrip(t *testing.T) {
	m := &Message{
		Seq:       "287",
		Timestamp: "1788020417755",
		PortMappingFrame: &PortMappingFrame{
			SessionID: "1",
			RuleID:    "1788015422013002",
			StreamID:  "1",
			Type:      TypeSynAck,
			Payload:   NewSynAck(),
		},
	}
	enc, _ := m.Encode()
	dec, err := DecodeMessage(enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	f := dec.PortMappingFrame
	if f.Type != TypeSynAck {
		t.Errorf("type = %q", f.Type)
	}
	if !bytes.Equal(f.Payload, []byte(`{"ok":true,"version":1}`)) {
		t.Errorf("payload = %q", f.Payload)
	}
}

// TestConnectWireMatchesOfficialCapture locks the direct FILE_DATA_CHANNEL
// protobuf encoding to bytes captured from the official macOS client.
func TestConnectWireMatchesOfficialCapture(t *testing.T) {
	m := &Message{
		Seq:       "5",
		Timestamp: "1788113829",
		PortMappingFrame: &PortMappingFrame{
			SessionID: "1",
			RuleID:    "1788015422013002",
			StreamID:  "1",
			Type:      TypeConnect,
			Payload:   NewConnect("127.0.0.1", 3389),
		},
	}
	enc, err := m.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	want, err := hex.DecodeString("080510a5e7d1d406da0149080110cafcd3c08cc6960318012a3a7b227461726765745f686f7374223a223132372e302e302e31222c227461726765745f706f7274223a333338392c2276657273696f6e223a317d")
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	if !bytes.Equal(enc, want) {
		t.Fatalf("wire mismatch:\n got %x\nwant %x", enc, want)
	}
}

func TestOfficialDataAndFinFramesDecode(t *testing.T) {
	cases := []struct {
		name     string
		wire     string
		wantType FrameType
		payload  []byte
	}{
		{
			name:     "DATA",
			wire:     "080610a5e7d1d406da0120080110cafcd3c08cc69603180120022a0f75756c696e6b2d747269676765720a",
			wantType: TypeData,
			payload:  []byte("uulink-trigger\n"),
		},
		{
			name:     "FIN",
			wire:     "080710a5e7d1d406da010f080110cafcd3c08cc6960318012001",
			wantType: TypeFin,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wire, err := hex.DecodeString(tc.wire)
			if err != nil {
				t.Fatalf("decode fixture: %v", err)
			}
			msg, err := DecodeMessage(wire)
			if err != nil {
				t.Fatalf("decode message: %v", err)
			}
			frame := msg.PortMappingFrame
			if frame == nil {
				t.Fatal("frame missing")
			}
			if frame.Type != tc.wantType {
				t.Fatalf("type = %q, want %q", frame.Type, tc.wantType)
			}
			if !bytes.Equal(frame.Payload, tc.payload) {
				t.Fatalf("payload = %q, want %q", frame.Payload, tc.payload)
			}
		})
	}
}

func TestDecodeMessageRejectsWrongFrameWireType(t *testing.T) {
	// Field 27 must be length-delimited; this encodes it as a varint.
	_, err := DecodeMessage([]byte{0xd8, 0x01, 0x00})
	if err == nil {
		t.Fatal("DecodeMessage() accepted a frame with the wrong wire type")
	}
}
