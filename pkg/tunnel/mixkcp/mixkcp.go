// Package mixkcp implements the UU Remote "mix-kcp" wire format observed on
// the PM (port mapping) UDP transport.
//
// This is a structural codec only. Session headers and the first byte come
// from each datagram, not from a universal sample. Encryption and the rolling
// first-byte algorithm have not been established; this package cannot create
// an interoperable encrypted PM request from plaintext.
package mixkcp

import (
	"fmt"
)

// HeaderLen is the fixed frame header size: 1 command byte + 17 session bytes.
const HeaderLen = 18

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

// NewFrame requires an explicit session header and already encoded payload.
// It validates framing, not cryptographic or upstream session validity.
func NewFrame(cmd byte, session, payload []byte) (*Frame, error) {
	if len(session) != HeaderLen-1 {
		return nil, fmt.Errorf("mixkcp: session header must be %d bytes", HeaderLen-1)
	}
	return &Frame{Cmd: cmd, Session: append([]byte(nil), session...), Payload: append([]byte(nil), payload...)}, nil
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
