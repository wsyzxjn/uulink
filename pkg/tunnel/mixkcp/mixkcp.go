// Package mixkcp implements the UU Remote "mix-kcp" wire format observed on
// the PM (port mapping) UDP transport.
//
// Wire layout (reverse-engineered from official client captures, 2026-08-30;
// see doc/uulink-findings.md section 9.8):
//
//	byte 0      : rolling command/checksum byte (differs per frame and per
//	              session even for identical message sizes)
//	bytes 1-17  : session header, constant 9d53ea4d6bb59b555c492f254512146e73
//	              across sessions (17 bytes starting after byte 0)
//	bytes 18+  : encrypted payload
//
// The 17-byte header constant was extracted from five captured PM frames
// (CONNECT/DATA/FIN) that all share it byte-for-byte.
package mixkcp

import (
	"encoding/hex"
	"fmt"
)

// HeaderLen is the fixed frame header size: 1 command byte + 17 session bytes.
const HeaderLen = 18

// SessionHeaderDefault is the session header shared by every captured PM frame.
var SessionHeaderDefault = mustDecodeHex("9d53ea4d6bb59b555c492f254512146e73")

// Frame is a parsed mix-kcp datagram.
type Frame struct {
	Cmd     byte   // byte 0: rolling command/checksum
	Session []byte // bytes 1..17 inclusive (17 bytes)
	Payload []byte // bytes 18+ (encrypted)
}

// ParseFrame splits a raw datagram into its structural parts. It only
// validates lengths; the session header value is preserved as-is so foreign
// headers (if any future capture shows one) still round-trip.
func ParseFrame(raw []byte) (*Frame, error) {
	if len(raw) < HeaderLen {
		return nil, fmt.Errorf("mixkcp: frame too short: %d bytes", len(raw))
	}
	f := &Frame{
		Cmd:     raw[0],
		Session: make([]byte, 17),
	}
	copy(f.Session, raw[1:18])
	f.Payload = make([]byte, len(raw)-HeaderLen)
	copy(f.Payload, raw[HeaderLen:])
	return f, nil
}

// Build reassembles the frame into wire bytes.
func (f *Frame) Build() []byte {
	out := make([]byte, 0, HeaderLen+len(f.Payload))
	out = append(out, f.Cmd)
	out = append(out, f.Session...)
	out = append(out, f.Payload...)
	return out
}

// NewFrame constructs a frame with the default session header.
func NewFrame(cmd byte, payload []byte) *Frame {
	sess := make([]byte, len(SessionHeaderDefault))
	copy(sess, SessionHeaderDefault)
	p := make([]byte, len(payload))
	copy(p, payload)
	return &Frame{Cmd: cmd, Session: sess, Payload: p}
}

// SplitCryptoRegion splits a frame payload region into the hypothesized
// kcp-go-style crypto layout: 8-byte plaintext nonce, 4-byte CRC32, and the
// ciphertext body. Offline decryption of captured frames was ruled out
// (per-frame nonces; no static XOR pad — see findings 9.13), but the layout
// helper keeps the structure explicit for the send path.
func SplitCryptoRegion(region []byte) (nonce, crc, body []byte) {
	if len(region) < 12 {
		return region, nil, nil
	}
	return region[:8], region[8:12], region[12:]
}

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("mixkcp: bad embedded hex: " + err.Error())
	}
	return b
}
