package mixkcp

import (
	"encoding/hex"
	"testing"
)

// Captured real PM frames from the official macOS client (2026-08-30, Round 10
// hook on sendto fd=85). Every frame shares the 17-byte session header
// 9d53ea4d6bb59b555c492f254512146e73 at offset 1; byte 0 varies per frame
// (rolling counter/checksum observed to differ across sessions for the same
// message size).
//
// Frame roles reconstructed from the matching stdout logs
// (sentProtocolBufferfile Message: {...}):
//
//	frame0 133B cmd 0x43 CONNECT (seq 55, streamId 13)
//	frame1  47B cmd 0x5d DATA (seq 56, payload "R10-INTERNAL-SSL")
//	frame2  92B cmd 0x50 (from the FIN sequence timing)
//	frame3  74B cmd 0x5d
//	frame4  47B cmd 0x4b FIN (seq 57)
var capturedFrames = []string{
	"439d53ea4d6bb59b555c492f254512146e734cb08bafa70471e9cec38bca8c6b29faa6ee0534cb2031e04295ac633f52f5baa8c91fd32173903745468511bb9b98149fc5f99694ab2619a994a85aa032f18e9aa9735ec18733f9c9b65c03c7cbffa6746350cfe822b8009c4178bde829070fe502946e24d3ee87b0117c2ccc99552b47ac07",
	"5d9d53ea4d6bb59b555c492f254512146e73f79525cb2de9ff539e5724ee92934a21536fc3d373bf0a51ee6078f9de",
	"509d53ea4d6bb59b555c492f254512146e73058498f083b330720a1dc2a2158d511164df463bbaeed3932c1457ae0b26afd5916f3f510ea845976b5299e90a5f3810aae99ea40d9eef7983f65c6ec5dcef455aa9694145b544557f72",
	"5d9d53ea4d6bb59b555c492f254512146e73fab9bac0184f7c35c18c66c3e8eea0b86b33f1a50494bfadffbc1547c8421caedbd50162c268161e7db86dcb87c97f989b3a7f9fa07a3646",
	"4b9d53ea4d6bb59b555c492f254512146e7327b72bdcc8e9900707aea8ab61518064998aed7e56c71f4c4b6888eb12",
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex fixture: %v", err)
	}
	return b
}

// TestParseRealFrames drives ParseFrame with the real captured bytes and
// asserts the structural fields against the known session header.
func TestParseRealFrames(t *testing.T) {
	for i, fx := range capturedFrames {
		raw := mustHex(t, fx)
		f, err := ParseFrame(raw)
		if err != nil {
			t.Fatalf("frame %d: parse: %v", i, err)
		}
		if len(f.Session) != len(SessionHeaderDefault) {
			t.Fatalf("frame %d: session header len = %d", i, len(f.Session))
		}
		for j := range SessionHeaderDefault {
			if f.Session[j] != SessionHeaderDefault[j] {
				t.Fatalf("frame %d: session byte %d = %#x, want %#x",
					i, j, f.Session[j], SessionHeaderDefault[j])
			}
		}
		if got := len(f.Payload); got != len(raw)-HeaderLen {
			t.Fatalf("frame %d: payload len = %d, want %d", i, got, len(raw)-HeaderLen)
		}
		// The whole raw frame must be recoverable from parsed fields.
		if f.Cmd != raw[0] {
			t.Fatalf("frame %d: cmd = %#x, want %#x", i, f.Cmd, raw[0])
		}
	}
}

// TestBuildRoundTrip asserts build(parse(x)) == x for every captured frame,
// proving the constructor reproduces the exact wire bytes.
func TestBuildRoundTrip(t *testing.T) {
	for i, fx := range capturedFrames {
		raw := mustHex(t, fx)
		f, err := ParseFrame(raw)
		if err != nil {
			t.Fatalf("frame %d: parse: %v", i, err)
		}
		built := f.Build()
		if len(built) != len(raw) {
			t.Fatalf("frame %d: built len %d, want %d", i, len(built), len(raw))
		}
		for j := range raw {
			if built[j] != raw[j] {
				t.Fatalf("frame %d: byte %d = %#x, want %#x (built=%s orig=%s)",
					i, j, built[j], raw[j],
					hex.EncodeToString(built[max(0, j-4):j+4]),
					hex.EncodeToString(raw[max(0, j-4):j+4]))
			}
		}
	}
}

// TestParseRejectsShortFrames guards against mis-parsing truncated datagrams.
func TestParseRejectsShortFrames(t *testing.T) {
	for _, n := range []int{0, 1, 5, 16} {
		if _, err := ParseFrame(make([]byte, n)); err == nil {
			t.Fatalf("ParseFrame(%d bytes) should fail", n)
		}
	}
	// Valid structure but session header mismatch must still parse structurally;
	// only length checks reject here. 17B header + 1 cmd = 18 bytes minimum.
	if _, err := ParseFrame(make([]byte, HeaderLen)); err != nil {
		t.Fatalf("minimal 18-byte frame should parse: %v", err)
	}
}
