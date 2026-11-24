//go:build integration

package tunnel

import (
	"errors"
	"github.com/wsyzxjn/uulink/pkg/proto/gvpb"
	"github.com/wsyzxjn/uulink/pkg/settings"
	"io"
	"net"
	"testing"
	"time"
)

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
	tunnelA, err := NewTunnelWithSettings([]Rule{{
		ID:         "2001",
		LocalHost:  "127.0.0.1",
		LocalPort:  0,
		TargetHost: "127.0.0.1",
		TargetPort: targetPort,
	}}, senderA, settings.Network{MaxInFlight: 2})
	if err != nil {
		t.Fatal(err)
	}
	// The configured window must bound actual DATA flow, not only a getter.
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

// ackFailingSender refuses DATA_ACK frames, as a transport that just failed
// would.
type ackFailingSender struct{ *channelSender }

func (s ackFailingSender) SendFrame(msg []byte) error {
	if f := decodeFrameForTunnel(msg); f != nil && f.Type == gvpb.TypeDataAck {
		return errors.New("transport down")
	}
	return s.channelSender.SendFrame(msg)
}

// The peer counts a DATA frame against its window until the DATA_ACK
// arrives, so a stream whose ACK cannot be sent is closed rather than left
// running one slot short for good.
func TestUnsentDataAckClosesStream(t *testing.T) {
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer targetLn.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := targetLn.Accept()
		if err != nil {
			return
		}
		accepted <- conn
	}()

	out := ackFailingSender{newChannelSender()}
	defer out.Close()
	tun := NewTunnelWithRules(nil, out)
	defer tun.Stop()

	connect, err := newConnectMsg("4001", "1", "127.0.0.1", targetLn.Addr().(*net.TCPAddr).Port)
	if err != nil {
		t.Fatal(err)
	}
	tun.HandleMessage(connect)
	if f := decodeFrameForTunnel(receiveFrame(t, out.ch)); f == nil || f.Type != gvpb.TypeSynAck {
		t.Fatalf("expected SYN_ACK, got %v", f)
	}
	var target net.Conn
	select {
	case target = <-accepted:
		defer target.Close()
	case <-time.After(time.Second):
		t.Fatal("target never accepted")
	}

	data, err := newDataMsg("4001", "1", []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	tun.HandleMessage(data)

	_ = target.SetReadDeadline(time.Now().Add(2 * time.Second))
	got, err := io.ReadAll(target)
	if err != nil || string(got) != "hello" {
		t.Fatalf("target read %q, %v; want the data followed by EOF", got, err)
	}
	if f := decodeFrameForTunnel(receiveFrame(t, out.ch)); f == nil || f.Type != gvpb.TypeFin {
		t.Fatalf("expected FIN, got %v", f)
	}
	if _, ok := tun.streams.Load(streamKey("4001", "1")); ok {
		t.Fatal("stream is still registered after its DATA_ACK failed")
	}
}

// With early data a local connection's bytes follow its CONNECT at once;
// otherwise they wait for the peer's SYN_ACK.
func TestEarlyDataSkipsSynAckWait(t *testing.T) {
	for _, c := range []struct {
		name  string
		early bool
	}{{"gated", false}, {"early", true}} {
		t.Run(c.name, func(t *testing.T) {
			sender := newChannelSender()
			defer sender.Close()
			tun := NewTunnelWithRules([]Rule{{ID: "5001", LocalHost: "127.0.0.1", TargetHost: "127.0.0.1", TargetPort: 9}}, sender)
			if c.early {
				tun.EnableEarlyData()
			}
			if err := tun.Start(); err != nil {
				t.Fatal(err)
			}
			defer tun.Stop()
			addr, err := tun.ListenerAddr("5001")
			if err != nil {
				t.Fatal(err)
			}
			conn, err := net.DialTimeout("tcp", addr.String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if f := decodeFrameForTunnel(receiveFrame(t, sender.ch)); f == nil || f.Type != gvpb.TypeConnect {
				t.Fatalf("expected CONNECT, got %v", f)
			}
			if _, err := conn.Write([]byte("hello")); err != nil {
				t.Fatal(err)
			}
			select {
			case raw := <-sender.ch:
				f := decodeFrameForTunnel(raw)
				if !c.early {
					t.Fatalf("frame sent before SYN_ACK: %v", f)
				}
				if f == nil || f.Type != gvpb.TypeData || string(f.Payload) != "hello" {
					t.Fatalf("expected early DATA, got %v", f)
				}
			case <-time.After(200 * time.Millisecond):
				if c.early {
					t.Fatal("early data waited for SYN_ACK")
				}
			}
		})
	}
}

// DATA that arrives before the target is connected waits for it instead of
// being dropped; early data depends on this.
func TestDataBeforeSynAckReachesTarget(t *testing.T) {
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer targetLn.Close()
	received := make(chan string, 1)
	go func() {
		conn, err := targetLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 16)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _ := io.ReadFull(conn, buf[:5])
		received <- string(buf[:n])
	}()

	out := newChannelSender()
	defer out.Close()
	tun := NewTunnelWithRules(nil, out)
	defer tun.Stop()

	connect, err := newConnectMsg("6001", "1", "127.0.0.1", targetLn.Addr().(*net.TCPAddr).Port)
	if err != nil {
		t.Fatal(err)
	}
	data, err := newDataMsg("6001", "1", []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	tun.HandleMessage(connect)
	tun.HandleMessage(data)

	select {
	case got := <-received:
		if got != "hello" {
			t.Fatalf("target received %q, want %q", got, "hello")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("target never received the early DATA")
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
