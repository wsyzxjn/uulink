package tunnel

import (
	"sync"
	"testing"
	"time"
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

func (m *mockSession) ID() string { return m.id }

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
	pool.AddSession(newMockSession("session-1"))
	pool.AddSession(newMockSession("session-2"))
	pool.AddSession(newMockSession("session-3"))
	pool.AddSession(newMockSession("session-3")) // duplicate IDs are ignored

	if n := pool.SessionCount(); n != 3 {
		t.Fatalf("expected 3 sessions, got %d", n)
	}

	c1, err1 := pool.SelectSession("1001", "1")
	c2, err2 := pool.SelectSession("1001", "2")
	c3, err3 := pool.SelectSession("1001", "3")
	if err1 != nil || err2 != nil || err3 != nil {
		t.Fatalf("select session failed: %v %v %v", err1, err2, err3)
	}
	if c1.ID() != "session-1" || c2.ID() != "session-2" || c3.ID() != "session-3" {
		t.Errorf("unexpected round robin: %s, %s, %s", c1.ID(), c2.ID(), c3.ID())
	}

	// Repeated queries for stream "1" must stay on session-1.
	c1Again, _ := pool.SelectSession("1001", "1")
	if c1Again.ID() != "session-1" {
		t.Errorf("stream affinity broken: expected session-1, got %s", c1Again.ID())
	}

	// The next new stream wraps around to session-1.
	c4, _ := pool.SelectSession("1001", "4")
	if c4.ID() != "session-1" {
		t.Errorf("wrap around failed: expected session-1, got %s", c4.ID())
	}
}

func TestSessionPoolLeastLoadedDispatch(t *testing.T) {
	pool := NewSessionPool(PolicyStreamLeastLoaded)
	pool.AddSession(newMockSession("s1"))
	pool.AddSession(newMockSession("s2"))

	if _, err := pool.SelectSession("rule", "1"); err != nil {
		t.Fatal(err)
	}
	c2, _ := pool.SelectSession("rule", "2")
	if c2.ID() != "s2" {
		t.Errorf("expected least loaded s2, got %s", c2.ID())
	}
	if _, err := pool.SelectSession("rule", "3"); err != nil {
		t.Fatal(err)
	}

	// Releasing stream 1 makes s1 the least loaded session again.
	pool.ReleaseStream("rule", "1")
	c4, _ := pool.SelectSession("rule", "4")
	if c4.ID() != "s1" {
		t.Errorf("expected least loaded s1, got %s", c4.ID())
	}
}

func TestSessionPoolBindStream(t *testing.T) {
	pool := NewSessionPool(PolicyStreamRoundRobin)
	s1 := newMockSession("s1")
	s2 := newMockSession("s2")
	pool.AddSession(s1)
	pool.AddSession(s2)

	pool.BindStream("rule1", "stream1", s2)
	chosen, err := pool.SelectSession("rule1", "stream1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if chosen.ID() != "s2" {
		t.Fatalf("expected session s2, got %s", chosen.ID())
	}
}

func TestSessionPoolSelectSessionWithoutSessions(t *testing.T) {
	pool := NewSessionPool(PolicyStreamLeastLoaded)
	if _, err := pool.SelectSession("rule", "1"); err == nil {
		t.Fatal("SelectSession() succeeded with an empty pool")
	}
}

func TestSessionPoolSendFrameRoutesByStream(t *testing.T) {
	pool := NewSessionPool(PolicyStreamRoundRobin)
	s1 := newMockSession("sess-1")
	s2 := newMockSession("sess-2")
	pool.AddSession(s1)
	pool.AddSession(s2)

	connect1, err := newConnectMsg("1001", "1", "127.0.0.1", 80)
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.SendFrame(connect1); err != nil {
		t.Fatalf("send connect 1: %v", err)
	}
	connect2, err := newConnectMsg("1001", "2", "127.0.0.1", 80)
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.SendFrame(connect2); err != nil {
		t.Fatalf("send connect 2: %v", err)
	}
	if s1.FrameCount() != 1 || s2.FrameCount() != 1 {
		t.Fatalf("connect frames: s1=%d s2=%d, want 1 each", s1.FrameCount(), s2.FrameCount())
	}

	// Data for stream 1 stays on the session its CONNECT used.
	data1, err := newDataMsg("1001", "1", []byte("stream-1-data"))
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.SendFrame(data1); err != nil {
		t.Fatalf("send data: %v", err)
	}
	if s1.FrameCount() != 2 || s2.FrameCount() != 1 {
		t.Fatalf("data frame routing: s1=%d s2=%d", s1.FrameCount(), s2.FrameCount())
	}

	// FIN is delivered on the same session and then releases the binding.
	fin1, err := newFINMsg("1001", "1")
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.SendFrame(fin1); err != nil {
		t.Fatalf("send fin: %v", err)
	}
	if s1.FrameCount() != 3 {
		t.Fatalf("fin frame routing: s1=%d, want 3", s1.FrameCount())
	}
	if _, loaded := pool.streamMap.Load(streamKey("1001", "1")); loaded {
		t.Fatal("stream 1 was not released after fin")
	}

	if err := pool.SendFrame([]byte{0xff, 0x00}); err == nil {
		t.Fatal("SendFrame() accepted a frame that is not a port mapping message")
	}
}

func TestAdaptiveSessionPoolDirectMode(t *testing.T) {
	expanded := false
	ap := NewAdaptiveSessionPool(4, PolicyStreamRoundRobin, func(int) error {
		expanded = true
		return nil
	})
	ap.Pool().AddSession(newMockSession("s0"))

	ap.OnModeDetected("direct")
	if ap.CurrentMode() != "direct" {
		t.Errorf("expected direct mode, got %s", ap.CurrentMode())
	}
	if expanded {
		t.Error("expandFn should not be called in direct mode")
	}
	if ap.Pool().SessionCount() != 1 {
		t.Errorf("expected 1 session, got %d", ap.Pool().SessionCount())
	}
}

func TestAdaptiveSessionPoolRelayModeExpandsOnce(t *testing.T) {
	targets := make(chan int, 2)
	ap := NewAdaptiveSessionPool(4, PolicyStreamRoundRobin, func(target int) error {
		targets <- target
		return nil
	})
	ap.Pool().AddSession(newMockSession("s0"))

	ap.OnModeDetected("relay")
	ap.OnModeDetected("relay") // a second detection must not expand again
	if ap.CurrentMode() != "relay" {
		t.Errorf("expected relay mode, got %s", ap.CurrentMode())
	}

	select {
	case target := <-targets:
		if target != 4 {
			t.Errorf("expected expand target 4, got %d", target)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for expandFn")
	}
	select {
	case <-targets:
		t.Fatal("expandFn was called twice")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestAdaptiveSessionPoolUserDisabled(t *testing.T) {
	expanded := false
	ap := NewAdaptiveSessionPool(1, PolicyStreamRoundRobin, func(int) error {
		expanded = true
		return nil
	})
	ap.Pool().AddSession(newMockSession("s0"))

	ap.OnModeDetected("relay")
	if expanded {
		t.Error("expandFn should not be called when targetSessions == 1")
	}
}

func TestAdaptiveSessionPoolWithoutExpansionCallbackStaysSingleSession(t *testing.T) {
	ap := NewAdaptiveSessionPool(4, PolicyStreamRoundRobin, nil)
	ap.Pool().AddSession(newMockSession("s0"))

	ap.OnModeDetected("relay")
	if got := ap.Pool().SessionCount(); got != 1 {
		t.Fatalf("session count = %d, want 1", got)
	}
	if ap.expanding {
		t.Fatal("pool marked as expanding without an expansion callback")
	}
}

func TestAdaptiveSessionPoolCloseClosesSessions(t *testing.T) {
	ap := NewAdaptiveSessionPool(2, PolicyStreamRoundRobin, nil)
	s0 := newMockSession("s0")
	ap.Pool().AddSession(s0)
	if err := ap.Close(); err != nil {
		t.Fatalf("Close(): %v", err)
	}
	if !s0.closed {
		t.Fatal("Close() did not close the pooled session")
	}
	if ap.Pool().SessionCount() != 0 {
		t.Fatal("Close() left sessions in the pool")
	}
}
