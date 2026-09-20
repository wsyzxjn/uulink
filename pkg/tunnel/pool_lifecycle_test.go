package tunnel

import (
	"bytes"
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// poolBoundCount reports how many stream bindings the pool currently holds.
func poolBoundCount(pool *SessionPool) int {
	n := 0
	pool.streamMap.Range(func(_, _ any) bool {
		n++
		return true
	})
	return n
}

func poolActiveCount(pool *SessionPool, sessionID string) int64 {
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	if ptr := pool.activeCounts[sessionID]; ptr != nil {
		return atomic.LoadInt64(ptr)
	}
	return 0
}

// A client that half-closes after its request must still receive a response
// larger than the DATA_ACK window: the pool binding has to survive this side's
// FIN so the acknowledgements for the peer's data keep flowing.
func TestPoolKeepsBindingForHalfCloseResponse(t *testing.T) {
	const respSize = 6 << 20 // > defaultMaxInFlight * 32 KiB
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
		_, _ = io.ReadAll(conn) // wait for the client's half-close
		_, _ = conn.Write(bytes.Repeat([]byte("x"), respSize))
	}()

	senderA := newChannelSender()
	senderB := newChannelSender()
	defer senderA.Close()
	defer senderB.Close()

	pool := NewSessionPool(PolicyStreamRoundRobin)
	pool.AddSession(NewSimpleSession("primary", senderA, nil))

	tunnelA := NewTunnelWithRules([]Rule{{
		ID: "4001", LocalHost: "127.0.0.1", LocalPort: 0,
		TargetHost: "127.0.0.1", TargetPort: targetLn.Addr().(*net.TCPAddr).Port,
	}}, pool)
	tunnelB := NewTunnelWithRules(nil, senderB)
	defer tunnelA.Stop()
	defer tunnelB.Stop()
	if err := tunnelA.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	senderA.Forward(tunnelB)
	senderB.Forward(tunnelA)

	addr, err := tunnelA.ListenerAddr("4001")
	if err != nil {
		t.Fatalf("listener addr: %v", err)
	}
	localConn, err := net.DialTimeout("tcp", addr.String(), time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer localConn.Close()
	if _, err := localConn.Write([]byte("GET")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := localConn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatalf("close write: %v", err)
	}

	localConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	got, err := io.ReadAll(localConn)
	if err != nil {
		t.Fatalf("read response: %v (got %d of %d bytes)", err, len(got), respSize)
	}
	if len(got) != respSize {
		t.Fatalf("got %d bytes, want %d", len(got), respSize)
	}

	// Once both sides finished, the binding must be gone.
	deadline := time.Now().Add(2 * time.Second)
	for poolBoundCount(pool) != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := poolBoundCount(pool); n != 0 {
		t.Fatalf("pool still holds %d stream binding(s) after both FINs", n)
	}
	if n := poolActiveCount(pool, "primary"); n != 0 {
		t.Fatalf("pool active count = %d after stream finished, want 0", n)
	}
}

// A CONNECT that the receiving side rejects (security policy or a failed dial)
// answers with SYN_ACK{ok:false} and never gets a FIN. The binding created for
// the incoming CONNECT must still be released.
func TestPoolReleasesBindingOnRejectedConnect(t *testing.T) {
	out := newChannelSender()
	defer out.Close()
	pool := NewSessionPool(PolicyHealthAware)
	sess := NewSimpleSession("primary", out, nil)
	pool.AddSession(sess)

	tun := NewTunnelWithRules(nil, pool)
	defer tun.Stop()
	tun.SetSecurityPolicy(SecurityPolicy{AllowLAN: false})

	// Policy rejection: synchronous.
	for i := 1; i <= 20; i++ {
		msg, err := newConnectMsg("7001", strconv.Itoa(i), "192.168.1.100", 8080)
		if err != nil {
			t.Fatal(err)
		}
		frame := DecodeFrameForTunnel(msg)
		pool.BindStream(frame.RuleID, frame.StreamID, sess) // mirrors the controlled side's OnSignalData
		tun.HandleFrame(frame)
		resp := decodeFrameForTunnel(receiveFrame(t, out.ch))
		if resp == nil || resp.Type != "SYN_ACK" {
			t.Fatalf("expected SYN_ACK, got %v", resp)
		}
	}
	if n := poolBoundCount(pool); n != 0 {
		t.Fatalf("policy rejection leaked %d binding(s)", n)
	}

	// Dial failure: asynchronous. A closed listener port refuses immediately.
	closedLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := closedLn.Addr().(*net.TCPAddr).Port
	closedLn.Close()
	for i := 1; i <= 20; i++ {
		msg, err := newConnectMsg("7002", strconv.Itoa(i), "127.0.0.1", closedPort)
		if err != nil {
			t.Fatal(err)
		}
		frame := DecodeFrameForTunnel(msg)
		pool.BindStream(frame.RuleID, frame.StreamID, sess)
		tun.HandleFrame(frame)
		resp := decodeFrameForTunnel(receiveFrame(t, out.ch))
		if resp == nil || resp.Type != "SYN_ACK" || !bytes.Contains(resp.Payload, []byte(`"ok":false`)) {
			t.Fatalf("expected negative SYN_ACK for refused dial, got %v", resp)
		}
	}
	deadline := time.Now().Add(2 * time.Second)
	for (poolBoundCount(pool) != 0 || poolActiveCount(pool, "primary") != 0) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := poolBoundCount(pool); n != 0 {
		t.Fatalf("dial failure leaked %d binding(s)", n)
	}
	if n := poolActiveCount(pool, "primary"); n != 0 {
		t.Fatalf("active count = %d after rejected connects, want 0", n)
	}
	if _, loaded := tun.streams.Load(streamKey("7002", "1")); loaded {
		t.Fatal("rejected stream is still in the stream table")
	}
}

// The CONNECT handler must not block the transport's receive path while the
// target is being dialed: a second stream on the same transport is served
// while the first dial is still pending.
func TestHandleConnectDialsAsynchronously(t *testing.T) {
	// A listener whose accept queue we never drain still completes the TCP
	// handshake, so use an unroutable address to get a slow dial instead.
	out := newChannelSender()
	defer out.Close()
	tun := NewTunnelWithRules(nil, out)
	defer tun.Stop()
	tun.SetSecurityPolicy(SecurityPolicy{AllowLAN: true})

	slow, err := newConnectMsg("8001", "1", "10.255.255.1", 9)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	tun.HandleMessage(slow)
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("HandleMessage blocked for %s on a slow dial", elapsed)
	}

	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		conn, err := echoLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()
	fast, err := newConnectMsg("8002", "1", "127.0.0.1", echoLn.Addr().(*net.TCPAddr).Port)
	if err != nil {
		t.Fatal(err)
	}
	tun.HandleMessage(fast)
	// The slow dial may fail fast on hosts without a route; only the fast
	// target's positive SYN_ACK matters, and it must not wait for the slow one.
	deadline := time.After(2 * time.Second)
	for {
		select {
		case raw := <-out.ch:
			resp := decodeFrameForTunnel(raw)
			if resp != nil && resp.RuleID == "8002" {
				if resp.Type != "SYN_ACK" || !bytes.Contains(resp.Payload, []byte(`"ok":true`)) {
					t.Fatalf("expected positive SYN_ACK for the fast target, got %v", resp)
				}
				return
			}
		case <-deadline:
			t.Fatal("fast target's SYN_ACK was held up by the slow dial")
		}
	}
}

// A stalled local application must only stall its own stream: DATA for a
// sibling stream on the same transport is still written.
func TestSlowLocalWriterDoesNotBlockSiblingStream(t *testing.T) {
	// Stream 1 targets a server that never reads, stream 2 an echo server.
	stuckLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer stuckLn.Close()
	stuckAccepted := make(chan net.Conn, 1)
	go func() {
		conn, err := stuckLn.Accept()
		if err != nil {
			return
		}
		stuckAccepted <- conn // held open, never read
	}()
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		conn, err := echoLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()

	out := newChannelSender()
	defer out.Close()
	tun := NewTunnelWithRules(nil, out)
	defer tun.Stop()

	for _, c := range []struct {
		rule string
		port int
	}{
		{"9001", stuckLn.Addr().(*net.TCPAddr).Port},
		{"9002", echoLn.Addr().(*net.TCPAddr).Port},
	} {
		msg, err := newConnectMsg(c.rule, "1", "127.0.0.1", c.port)
		if err != nil {
			t.Fatal(err)
		}
		tun.HandleMessage(msg)
		if resp := decodeFrameForTunnel(receiveFrame(t, out.ch)); resp == nil || resp.Type != "SYN_ACK" {
			t.Fatalf("rule %s: expected SYN_ACK, got %v", c.rule, resp)
		}
	}
	select {
	case conn := <-stuckAccepted:
		defer conn.Close()
	case <-time.After(time.Second):
		t.Fatal("stuck target never accepted")
	}

	// Fill the stuck stream's socket buffers and its inbox far beyond what the
	// kernel will absorb, from a goroutine, since enqueue blocks once full.
	chunk := bytes.Repeat([]byte("s"), 32*1024)
	go func() {
		for i := 0; i < 4*inboundQueueDepth; i++ { // 16 MiB: far beyond loopback socket buffers
			msg, _ := newDataMsg("9001", "1", chunk)
			tun.HandleMessage(msg)
		}
	}()
	time.Sleep(200 * time.Millisecond)

	// The sibling stream must still round-trip promptly.
	msg, err := newDataMsg("9002", "1", []byte("ping"))
	if err != nil {
		t.Fatal(err)
	}
	tun.HandleMessage(msg)
	deadline := time.After(2 * time.Second)
	for {
		select {
		case raw := <-out.ch:
			f := decodeFrameForTunnel(raw)
			if f != nil && f.RuleID == "9002" && f.Type == "DATA" && string(f.Payload) == "ping" {
				return
			}
		case <-deadline:
			t.Fatal("sibling stream starved by a stalled local writer")
		}
	}
}
