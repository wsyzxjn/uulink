// Package mixsend implements the mix-kcp UDP send path: writing PM frames to
// the ICE-selected peer address over a local UDP socket.
//
// The official client sends PM frames via the SAME UDP socket/path that ICE
// selected for the WebRTC connection (captured 2026-08-30: sendto(fd=85) with
// DTLS media traffic interleaved on the same socket). The session header
// (17 bytes) and command byte are plaintext; the payload region carries the
// kcp-go-style crypto layout (8B nonce + 4B CRC + body — see findings 9.13).
package mixsend

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/user/uulink/pkg/tunnel/mixkcp"
)

// Sender writes mix-kcp frames to a fixed UDP peer.
type Sender struct {
	conn *net.UDPConn
	peer *net.UDPAddr
}

// NewSender binds an ephemeral UDP socket and targets peer.
func NewSender(peer *net.UDPAddr) (*Sender, error) {
	conn, err := net.DialUDP("udp", nil, peer)
	if err != nil {
		return nil, fmt.Errorf("mixsend dial %s: %w", peer, err)
	}
	return &Sender{conn: conn, peer: peer}, nil
}

// SendPMFrame wraps payload in a mix-kcp frame (default session header) and
// writes it to the peer. The command byte is currently fixed at 0x43 — the
// CONNECT command observed in captures; per-frame rolling behavior of byte 0
// is not yet reverse-engineered.
func (s *Sender) SendPMFrame(cmd byte, payload []byte) error {
	f := mixkcp.NewFrame(cmd, payload)
	wire := f.Build()
	n, err := s.conn.Write(wire)
	if err != nil {
		return fmt.Errorf("mixsend write: %w", err)
	}
	if n != len(wire) {
		return fmt.Errorf("mixsend short write: %d/%d", n, len(wire))
	}
	log.Printf("[mixkcp] sent frame to %s: cmd=%#x len=%d hex=%s",
		s.peer, cmd, len(wire), hex.EncodeToString(wire))
	return nil
}

// ReceivePMFrame blocks for one datagram and parses it as a mix-kcp frame.
func (s *Sender) ReceivePMFrame() (*mixkcp.Frame, error) {
	buf := make([]byte, 2048)
	n, err := s.conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("mixsend read: %w", err)
	}
	f, err := mixkcp.ParseFrame(buf[:n])
	if err != nil {
		return nil, fmt.Errorf("mixsend parse (%d bytes): %w", n, err)
	}
	log.Printf("[mixkcp] received frame: cmd=%#x session=%s len=%d hex=%s",
		f.Cmd, hex.EncodeToString(f.Session), n, hex.EncodeToString(buf[:n]))
	return f, nil
}

// SetReadDeadline bounds ReceivePMFrame waits.
func (s *Sender) SetReadDeadline(t time.Time) {
	_ = s.conn.SetReadDeadline(t)
}

// Close closes the underlying socket.
func (s *Sender) Close() error {
	return s.conn.Close()
}
