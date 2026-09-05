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
