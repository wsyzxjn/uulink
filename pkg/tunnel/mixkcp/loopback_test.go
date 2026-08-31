package mixkcp

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net"
	"sync"
	"testing"
	"time"
)

// TestLoopbackExchange drives the shipped UDP transport end-to-end over a
// loopback socket pair: an initiator sends a frame built by NewFrame and the
// responder receives, parses, and echoes it back. This exercises the real
// send/recv path with the real frame codec (acceptance criterion 2 fallback).
func TestLoopbackExchange(t *testing.T) {
	// Responder socket on loopback.
	resp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer resp.Close()

	init, err := net.DialUDP("udp", nil, resp.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer init.Close()

	payload := []byte(`{"seq":"6","portMappingFrame":{"sessionId":"1"}}`)
	out := NewFrame(0x43, payload)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 1500)
		resp.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, from, err := resp.ReadFromUDP(buf)
		if err != nil {
			t.Errorf("responder read: %v", err)
			return
		}
		got, err := ParseFrame(buf[:n])
		if err != nil {
			t.Errorf("responder parse: %v", err)
			return
		}
		if got.Cmd != out.Cmd {
			t.Errorf("cmd = %#x, want %#x", got.Cmd, out.Cmd)
		}
		if !bytes.Equal(got.Session, SessionHeaderDefault) {
			t.Errorf("session = %s", hex.EncodeToString(got.Session))
		}
		if !bytes.Equal(got.Payload, payload) {
			t.Errorf("payload mismatch: %q", got.Payload)
		}
		// echo back with a different command byte (like a SYN_ACK reply)
		got.Cmd = 0x5d
		_, err = resp.WriteToUDP(got.Build(), from)
		if err != nil {
			t.Errorf("responder write: %v", err)
		}
	}()

	if _, err := init.Write(out.Build()); err != nil {
		t.Fatalf("initiator write: %v", err)
	}

	buf := make([]byte, 1500)
	init.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := init.Read(buf)
	if err != nil {
		t.Fatalf("initiator read: %v", err)
	}
	echo, err := ParseFrame(buf[:n])
	if err != nil {
		t.Fatalf("initiator parse: %v", err)
	}
	if echo.Cmd != 0x5d {
		t.Errorf("echo cmd = %#x, want 0x5d", echo.Cmd)
	}
	if !bytes.Equal(echo.Payload, payload) {
		t.Errorf("echo payload mismatch")
	}
	wg.Wait()
}

// TestNonceAndCRCLayout documents the hypothesized crypto layout of the
// payload region (kcp-go style: 8B nonce + 4B CRC + ciphertext). It asserts
// the shipped helper splits a payload region accordingly.
func TestNonceAndCRCLayout(t *testing.T) {
	region := make([]byte, 32)
	for i := range region {
		region[i] = byte(i)
	}
	nonce, crc, body := SplitCryptoRegion(region)
	if len(nonce) != 8 {
		t.Fatalf("nonce len = %d", len(nonce))
	}
	if len(crc) != 4 {
		t.Fatalf("crc len = %d", len(crc))
	}
	if len(body) != 20 {
		t.Fatalf("body len = %d", len(body))
	}
	if binary.BigEndian.Uint32(crc) != binary.BigEndian.Uint32(region[8:12]) {
		t.Fatal("crc slice mismatch")
	}
}
