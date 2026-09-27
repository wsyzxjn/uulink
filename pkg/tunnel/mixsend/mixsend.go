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
	"fmt"
	"net"
	"time"

	"github.com/wsyzxjn/uulink/pkg/logging"
	"github.com/wsyzxjn/uulink/pkg/tunnel/mixkcp"
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

// SendFrame sends a caller-provided complete datagram without synthesizing
// a command byte, session header or ciphertext from unrelated capture samples.
func (s *Sender) SendFrame(wire []byte) error {
	if _, err := mixkcp.ParseFrame(wire); err != nil {
		return err
	}
	n, err := s.conn.Write(wire)
	if err != nil {
		return fmt.Errorf("mixsend write: %w", err)
	}
	if n != len(wire) {
		return fmt.Errorf("mixsend short write: %d/%d", n, len(wire))
	}
	return nil
}

// ReceivePMFrame blocks for one datagram and parses it as a mix-kcp frame.
func (s *Sender) ReceivePMFrame() (*mixkcp.Frame, error) {
	buf := make([]byte, 65535)
	n, err := s.conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("mixsend read: %w", err)
	}
	f, err := mixkcp.ParseFrame(buf[:n])
	if err != nil {
		return nil, fmt.Errorf("mixsend parse (%d bytes): %w", n, err)
	}
	logging.Debugf("[mixkcp] received frame: cmd=%#x len=%d", f.Cmd, n)
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
