package tunnel

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

type channelSender struct {
	ch   chan []byte
	done chan struct{}
}

func newChannelSender() *channelSender {
	return &channelSender{ch: make(chan []byte, 64), done: make(chan struct{})}
}

func (s *channelSender) SendFrame(msg []byte) error {
	select {
	case s.ch <- msg:
		return nil
	case <-s.done:
		return fmt.Errorf("sender closed")
	}
}

func (s *channelSender) Close() {
	select {
	case <-s.done:
	default:
		close(s.done)
	}
}

func (s *channelSender) Forward(t *Tunnel) {
	go func() {
		for {
			select {
			case msg := <-s.ch:
				t.HandleMessage(msg)
			case <-s.done:
				return
			}
		}
	}()
}

func TestSymmetricTunnelConnectDataAndFin(t *testing.T) {
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	defer targetLn.Close()
	go func() {
		for {
			conn, err := targetLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()

	senderA := newChannelSender()
	senderB := newChannelSender()
	tunnelA := NewTunnelWithRules([]Rule{{
		ID:         "1001",
		LocalHost:  "127.0.0.1",
		LocalPort:  0,
		TargetHost: "127.0.0.1",
		TargetPort: targetLn.Addr().(*net.TCPAddr).Port,
	}}, senderA)
	if err := tunnelA.Start(); err != nil {
		t.Fatalf("start tunnel A: %v", err)
	}
	defer tunnelA.Stop()

	tunnelB := NewTunnelWithRules(nil, senderB)
	defer tunnelB.Stop()

	listenerAddr, err := tunnelA.ListenerAddr("1001")
	if err != nil {
		t.Fatalf("listener addr: %v", err)
	}
	localConn, err := net.DialTimeout("tcp", listenerAddr.String(), time.Second)
	if err != nil {
		t.Fatalf("dial local listener: %v", err)
	}
	defer localConn.Close()

	connect := receiveFrame(t, senderA.ch)
	tunnelB.HandleMessage(connect)

	synAck := receiveFrame(t, senderB.ch)
	tunnelA.HandleMessage(synAck)

	if _, err := localConn.Write([]byte("ping")); err != nil {
		t.Fatalf("write local: %v", err)
	}
	data := receiveFrame(t, senderA.ch)
	tunnelB.HandleMessage(data)

	echo := receiveDataFrame(t, senderB.ch)
	tunnelA.HandleMessage(echo)

	localConn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 4)
	if _, err := io.ReadFull(localConn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo = %q, want ping", string(buf))
	}

	if err := localConn.Close(); err != nil {
		t.Fatalf("close local: %v", err)
	}
	fin := receiveFrame(t, senderA.ch)
	tunnelB.HandleMessage(fin)
}

func receiveFrame(t *testing.T, ch chan []byte) []byte {
	t.Helper()
	select {
	case msg := <-ch:
		return msg
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for PM frame")
		return nil
	}
}

func receiveDataFrame(t *testing.T, ch chan []byte) []byte {
	t.Helper()
	for {
		msg := receiveFrame(t, ch)
		if frame := decodeFrameForTunnel(msg); frame != nil && frame.Type == "DATA" {
			return msg
		}
	}
}

func TestTunnelForwardsMultipleRulesConcurrently(t *testing.T) {
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	defer targetLn.Close()
	go func() {
		for {
			conn, err := targetLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()

	senderA := newChannelSender()
	senderB := newChannelSender()
	defer senderA.Close()
	defer senderB.Close()

	targetPort := targetLn.Addr().(*net.TCPAddr).Port
	tunnelA := NewTunnelWithRules([]Rule{
		{ID: "1101", LocalHost: "127.0.0.1", LocalPort: 0, TargetHost: "127.0.0.1", TargetPort: targetPort},
		{ID: "1102", LocalHost: "127.0.0.1", LocalPort: 0, TargetHost: "127.0.0.1", TargetPort: targetPort},
	}, senderA)
	tunnelB := NewTunnelWithRules(nil, senderB)
	defer tunnelA.Stop()
	defer tunnelB.Stop()

	if err := tunnelA.Start(); err != nil {
		t.Fatalf("start multi-rule tunnel: %v", err)
	}
	senderA.Forward(tunnelB)
	senderB.Forward(tunnelA)

	addr1, err := tunnelA.ListenerAddr("1101")
	if err != nil {
		t.Fatalf("listener 1101: %v", err)
	}
	addr2, err := tunnelA.ListenerAddr("1102")
	if err != nil {
		t.Fatalf("listener 1102: %v", err)
	}

	echoes := make(chan string, 2)
	go echoTCP(t, addr1.String(), "rule-one", echoes)
	go echoTCP(t, addr2.String(), "rule-two", echoes)
	for range 2 {
		select {
		case echo := <-echoes:
			if echo != "rule-one" && echo != "rule-two" {
				t.Fatalf("unexpected echo %q", echo)
			}
		case <-time.After(time.Second):
			t.Fatal("timeout waiting for multi-rule echoes")
		}
	}
}

func echoTCP(t *testing.T, address, payload string, result chan<- string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		result <- "dial error: " + err.Error()
		return
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(payload)); err != nil {
		result <- "write error: " + err.Error()
		return
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		result <- "read error: " + err.Error()
		return
	}
	result <- string(buf)
}

func TestTunnelFlowControlBackpressure(t *testing.T) {
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	defer targetLn.Close()

	senderA := newChannelSender()
	defer senderA.Close()

	targetPort := targetLn.Addr().(*net.TCPAddr).Port
	tunnelA := NewTunnelWithRules([]Rule{{
		ID:         "2001",
		LocalHost:  "127.0.0.1",
		LocalPort:  0,
		TargetHost: "127.0.0.1",
		TargetPort: targetPort,
	}}, senderA)
	// Limit window to 2 in-flight frames
	tunnelA.SetMaxInFlight(2)
	if tunnelA.MaxInFlight() != 2 {
		t.Fatalf("MaxInFlight = %d, want 2", tunnelA.MaxInFlight())
	}
	if err := tunnelA.Start(); err != nil {
		t.Fatalf("start tunnel: %v", err)
	}
	defer tunnelA.Stop()

	listenerAddr, err := tunnelA.ListenerAddr("2001")
	if err != nil {
		t.Fatalf("listener addr: %v", err)
	}
	localConn, err := net.DialTimeout("tcp", listenerAddr.String(), time.Second)
	if err != nil {
		t.Fatalf("dial local listener: %v", err)
	}
	defer localConn.Close()

	// 1. Consume CONNECT frame and emulate remote SYN_ACK
	_ = receiveFrame(t, senderA.ch)
	synAck, err := newSynAckMsg("2001", "1", true)
	if err != nil {
		t.Fatalf("synAck msg: %v", err)
	}
	tunnelA.HandleMessage(synAck)

	// 2. Write 2 chunks to localConn (should be emitted immediately)
	if _, err := localConn.Write([]byte("chunk1")); err != nil {
		t.Fatalf("write chunk1: %v", err)
	}
	f1 := receiveDataFrame(t, senderA.ch)
	if f1 == nil {
		t.Fatal("expected frame 1")
	}

	if _, err := localConn.Write([]byte("chunk2")); err != nil {
		t.Fatalf("write chunk2: %v", err)
	}
	f2 := receiveDataFrame(t, senderA.ch)
	if f2 == nil {
		t.Fatal("expected frame 2")
	}

	// 3. Write chunk3. Since in-flight is 2 (equal to window limit), readLoop must block
	if _, err := localConn.Write([]byte("chunk3")); err != nil {
		t.Fatalf("write chunk3: %v", err)
	}

	select {
	case msg := <-senderA.ch:
		if f := decodeFrameForTunnel(msg); f != nil && f.Type == "DATA" {
			t.Fatalf("expected backpressure to block chunk3, but got frame: %v", f)
		}
	case <-time.After(100 * time.Millisecond):
		// Expected: paused by backpressure
	}

	// 4. Send 1 DATA_ACK to acknowledge one frame
	ackMsg, err := newACKMsg("2001", "1")
	if err != nil {
		t.Fatalf("ack msg: %v", err)
	}
	tunnelA.HandleMessage(ackMsg)

	// 5. chunk3 should now be unblocked and sent
	select {
	case msg := <-senderA.ch:
		if f := decodeFrameForTunnel(msg); f == nil || f.Type != "DATA" || string(f.Payload) != "chunk3" {
			t.Fatalf("expected chunk3 DATA frame, got: %v", f)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for chunk3 after DATA_ACK")
	}
}

func TestTunnelTCPHalfClose(t *testing.T) {
	// Target server reads request until EOF, then sends response and closes.
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	defer targetLn.Close()
	go func() {
		conn, err := targetLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		req, _ := io.ReadAll(conn)
		_, _ = conn.Write(append([]byte("ack:"), req...))
	}()

	senderA := newChannelSender()
	senderB := newChannelSender()
	defer senderA.Close()
	defer senderB.Close()

	targetPort := targetLn.Addr().(*net.TCPAddr).Port
	tunnelA := NewTunnelWithRules([]Rule{{
		ID:         "3001",
		LocalHost:  "127.0.0.1",
		LocalPort:  0,
		TargetHost: "127.0.0.1",
		TargetPort: targetPort,
	}}, senderA)
	tunnelB := NewTunnelWithRules(nil, senderB)
	defer tunnelA.Stop()
	defer tunnelB.Stop()

	if err := tunnelA.Start(); err != nil {
		t.Fatalf("start tunnel: %v", err)
	}
	senderA.Forward(tunnelB)
	senderB.Forward(tunnelA)

	listenerAddr, err := tunnelA.ListenerAddr("3001")
	if err != nil {
		t.Fatalf("listener addr: %v", err)
	}
	localConn, err := net.DialTimeout("tcp", listenerAddr.String(), time.Second)
	if err != nil {
		t.Fatalf("dial local listener: %v", err)
	}
	defer localConn.Close()

	// Write request and half-close client write side
	if _, err := localConn.Write([]byte("request-data")); err != nil {
		t.Fatalf("write local: %v", err)
	}
	if tcpConn, ok := localConn.(*net.TCPConn); ok {
		if err := tcpConn.CloseWrite(); err != nil {
			t.Fatalf("close write: %v", err)
		}
	}

	// Read response back through half-closed socket
	localConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp, err := io.ReadAll(localConn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if string(resp) != "ack:request-data" {
		t.Fatalf("response = %q, want %q", string(resp), "ack:request-data")
	}
}
