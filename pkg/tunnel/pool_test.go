package tunnel

import (
	"context"
	"time"
	"bytes"
		"sync"
	"testing"
)

type mockSession struct {
	id     string
	mu     sync.Mutex
	frames [][]byte
	closed bool
}

func newMockSession(id string) *mockSession {
	return &mockSession{id: id}
}

func (m *mockSession) ID() string {
	return m.id
}

func (m *mockSession) SendFrame(msg []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.frames = append(m.frames, append([]byte(nil), msg...))
	return nil
}

func (m *mockSession) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func (m *mockSession) FrameCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.frames)
}

func TestSessionPoolRoundRobinDispatch(t *testing.T) {
	pool := NewSessionPool(PolicyStreamRoundRobin)
	s1 := newMockSession("session-1")
	s2 := newMockSession("session-2")
	s3 := newMockSession("session-3")

	pool.AddSession(s1)
	pool.AddSession(s2)
	pool.AddSession(s3)

	if n := pool.SessionCount(); n != 3 {
		t.Fatalf("expected 3 sessions, got %d", n)
	}

	// 3 streams should be assigned to s1, s2, s3
	c1, err1 := pool.SelectSession("1001", "1")
	c2, err2 := pool.SelectSession("1001", "2")
	c3, err3 := pool.SelectSession("1001", "3")
	if err1 != nil || err2 != nil || err3 != nil {
		t.Fatalf("select session failed: %v %v %v", err1, err2, err3)
	}

	if c1.ID() != "session-1" || c2.ID() != "session-2" || c3.ID() != "session-3" {
		t.Errorf("unexpected round robin: %s, %s, %s", c1.ID(), c2.ID(), c3.ID())
	}

	// Repeated queries for stream "1" must stay on session-1
	c1Again, _ := pool.SelectSession("1001", "1")
	if c1Again.ID() != "session-1" {
		t.Errorf("stream affinity broken: expected session-1, got %s", c1Again.ID())
	}

	// Next new stream wraps around to session-1
	c4, _ := pool.SelectSession("1001", "4")
	if c4.ID() != "session-1" {
		t.Errorf("wrap around failed: expected session-1, got %s", c4.ID())
	}

	// Release stream
	pool.ReleaseStream("1001", "1")
}

func TestSessionPoolLeastLoadedDispatch(t *testing.T) {
	pool := NewSessionPool(PolicyStreamLeastLoaded)
	s1 := newMockSession("s1")
	s2 := newMockSession("s2")
	pool.AddSession(s1)
	pool.AddSession(s2)

	// Stream 1 goes to s1
	_, _ = pool.SelectSession("rule", "1")
	// Stream 2 should go to s2
	c2, _ := pool.SelectSession("rule", "2")
	if c2.ID() != "s2" {
		t.Errorf("expected least loaded s2, got %s", c2.ID())
	}

	// Stream 3 can go to s1 or s2 (both count 1)
	_, _ = pool.SelectSession("rule", "3")

	// Release stream 1
	pool.ReleaseStream("rule", "1")

	// Now s1 has 1 (or 0) active stream, next stream should prefer s1
	c4, _ := pool.SelectSession("rule", "4")
	if c4.ID() != "s1" {
		t.Errorf("expected least loaded s1, got %s", c4.ID())
	}
}

func TestReorderBufferInOrderAndOutOfOrder(t *testing.T) {
	rb := NewReorderBuffer()

	// In order: 0
	r0 := rb.Insert(0, []byte("chunk-0"))
	if len(r0) != 1 || string(r0[0]) != "chunk-0" {
		t.Fatalf("expected chunk-0, got %v", r0)
	}

	// Out of order: deliver 2 then 3 then 1
	r2 := rb.Insert(2, []byte("chunk-2"))
	if len(r2) != 0 {
		t.Fatalf("expected empty (waiting for 1), got %v", r2)
	}

	r3 := rb.Insert(3, []byte("chunk-3"))
	if len(r3) != 0 {
		t.Fatalf("expected empty (waiting for 1), got %v", r3)
	}

	// Delivering 1 should flush 1, 2, 3 in sequence
	r1 := rb.Insert(1, []byte("chunk-1"))
	if len(r1) != 3 {
		t.Fatalf("expected 3 chunks flushed, got %d", len(r1))
	}
	expected := []string{"chunk-1", "chunk-2", "chunk-3"}
	for i, chunk := range r1 {
		if string(chunk) != expected[i] {
			t.Errorf("index %d: expected %s, got %s", i, expected[i], string(chunk))
		}
	}

	// Duplicate of already consumed chunk should be dropped
	dup := rb.Insert(1, []byte("dup-chunk-1"))
	if len(dup) != 0 {
		t.Fatalf("expected duplicate to be dropped, got %v", dup)
	}
}

func TestStripedPayloadEncoding(t *testing.T) {
	payload := []byte("hello-striped-network-world")
	seq := uint32(42)

	encoded := EncodeStripedPayload(seq, payload)
	decSeq, decPayload, isStriped := DecodeStripedPayload(encoded)

	if !isStriped {
		t.Fatal("expected isStriped to be true")
	}
	if decSeq != seq {
		t.Errorf("expected seq %d, got %d", seq, decSeq)
	}
	if !bytes.Equal(decPayload, payload) {
		t.Errorf("payload mismatch: %s vs %s", decPayload, payload)
	}

	// Plain payload without magic
	plain := []byte("plain-unstriped")
	_, _, plainIsStriped := DecodeStripedPayload(plain)
	if plainIsStriped {
		t.Errorf("plain payload was falsely detected as striped")
	}
}

func TestPoolTunnelRouting(t *testing.T) {
	pool := NewSessionPool(PolicyStreamRoundRobin)
	s1 := newMockSession("sess-1")
	s2 := newMockSession("sess-2")
	pool.AddSession(s1)
	pool.AddSession(s2)

	rule := Rule{ID: "1001", LocalPort: 0, TargetHost: "127.0.0.1", TargetPort: 80}
	pt := NewPoolTunnel([]Rule{rule}, pool)
	defer pt.Stop()

	// Send connect for stream 1
	cMsg1, _ := newConnectMsg("1001", "1", "127.0.0.1", 80)
	adapter := &poolSenderAdapter{pool: pool}
	if err := adapter.SendFrame(cMsg1); err != nil {
		t.Fatalf("send cMsg1: %v", err)
	}

	// Send connect for stream 2
	cMsg2, _ := newConnectMsg("1001", "2", "127.0.0.1", 80)
	if err := adapter.SendFrame(cMsg2); err != nil {
		t.Fatalf("send cMsg2: %v", err)
	}

	// s1 should receive stream 1 connect, s2 should receive stream 2 connect
	if s1.FrameCount() != 1 {
		t.Errorf("s1 expected 1 frame, got %d", s1.FrameCount())
	}
	if s2.FrameCount() != 1 {
		t.Errorf("s2 expected 1 frame, got %d", s2.FrameCount())
	}

	// Data for stream 1 must go to s1
	dMsg1, _ := newDataMsg("1001", "1", []byte("stream-1-data"))
	_ = adapter.SendFrame(dMsg1)
	if s1.FrameCount() != 2 {
		t.Errorf("s1 expected 2 frames after data, got %d", s1.FrameCount())
	}
	if s2.FrameCount() != 1 {
		t.Errorf("s2 frame count should remain 1, got %d", s2.FrameCount())
	}

	// Fin for stream 1
	finMsg1, _ := newFINMsg("1001", "1")
	_ = adapter.SendFrame(finMsg1)
	if s1.FrameCount() != 3 {
		t.Errorf("s1 expected 3 frames after fin, got %d", s1.FrameCount())
	}

	// Stream 1 should now be released from pool map
	key := streamKey("1001", "1")
	if _, loaded := pool.streamMap.Load(key); loaded {
		t.Errorf("stream 1 was not released after fin")
	}
}



func TestAdaptiveSessionPoolDirectMode(t *testing.T) {
	expanded := false
	expandFn := func(ctx context.Context, target int) error {
		expanded = true
		return nil
	}

	ap := NewAdaptiveSessionPool(4, PolicyStreamRoundRobin, expandFn)
	ap.Pool().AddSession(newMockSession("s0"))

	ap.OnModeDetected("direct")
	if ap.CurrentMode() != "direct" {
		t.Errorf("expected direct mode, got %s", ap.CurrentMode())
	}
	if expanded {
		t.Errorf("expandFn should not be called in direct mode")
	}
	if ap.Pool().SessionCount() != 1 {
		t.Errorf("expected 1 session, got %d", ap.Pool().SessionCount())
	}
}

func TestAdaptiveSessionPoolRelayMode(t *testing.T) {
	var mu sync.Mutex
	expandTarget := 0
	expandCalled := make(chan struct{})

	expandFn := func(ctx context.Context, target int) error {
		mu.Lock()
		expandTarget = target
		mu.Unlock()
		close(expandCalled)
		return nil
	}

	ap := NewAdaptiveSessionPool(4, PolicyStreamRoundRobin, expandFn)
	ap.Pool().AddSession(newMockSession("s0"))

	ap.OnModeDetected("relay")
	if ap.CurrentMode() != "relay" {
		t.Errorf("expected relay mode, got %s", ap.CurrentMode())
	}

	select {
	case <-expandCalled:
		mu.Lock()
		if expandTarget != 4 {
			t.Errorf("expected expand target 4, got %d", expandTarget)
		}
		mu.Unlock()
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for expandFn")
	}
}

func TestAdaptiveSessionPoolUserDisabled(t *testing.T) {
	expanded := false
	expandFn := func(ctx context.Context, target int) error {
		expanded = true
		return nil
	}

	ap := NewAdaptiveSessionPool(1, PolicyStreamRoundRobin, expandFn)
	ap.Pool().AddSession(newMockSession("s0"))

	ap.OnModeDetected("relay")
	if expanded {
		t.Errorf("expandFn should not be called when targetSessions == 1")
	}
}
