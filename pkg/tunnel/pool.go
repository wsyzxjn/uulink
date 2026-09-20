package tunnel

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wsyzxjn/uulink/pkg/logging"
	"github.com/wsyzxjn/uulink/pkg/proto/gvpb"
)

// Session is one independent WebRTC data path, typically backed by its own
// TURN allocation.
type Session interface {
	ID() string
	SendFrame(msg []byte) error
	Close() error
}

// DispatchPolicy selects the session for a new stream. All later DATA and FIN
// frames of that stream stay on the chosen session, which preserves in-order
// delivery without any reassembly.
type DispatchPolicy int

const (
	// PolicyStreamRoundRobin assigns each new stream to the next session.
	PolicyStreamRoundRobin DispatchPolicy = iota
	// PolicyStreamLeastLoaded assigns each new stream to the session with the
	// fewest active streams.
	PolicyStreamLeastLoaded
	// PolicyHealthAware prefers sessions with recent receive throughput and
	// penalizes sessions that already carry active streams.
	PolicyHealthAware
)

// SimpleSession adapts a FrameSender and an optional close function to Session.
type SimpleSession struct {
	id     string
	sender FrameSender
	closer func() error
}

// NewSimpleSession constructs a Session from a FrameSender. closer may be nil
// when the caller owns the underlying connection's lifetime.
func NewSimpleSession(id string, sender FrameSender, closer func() error) *SimpleSession {
	return &SimpleSession{id: id, sender: sender, closer: closer}
}

// ID returns the session identifier.
func (s *SimpleSession) ID() string { return s.id }

// SendFrame sends a protobuf wire-format message through the session.
func (s *SimpleSession) SendFrame(msg []byte) error { return s.sender.SendFrame(msg) }

// Close terminates the session.
func (s *SimpleSession) Close() error {
	if s.closer != nil {
		return s.closer()
	}
	return nil
}

// SessionPool multiplexes tunnel streams over several sessions so a pooled
// deployment is not limited by a single TURN allocation's rate cap.
type SessionPool struct {
	mu           sync.RWMutex
	sessions     []Session
	policy       DispatchPolicy
	rrIndex      atomic.Uint64
	streamMap    sync.Map // stream key -> Session
	activeCounts map[string]*int64
	received     sync.Map // session ID -> *atomic.Uint64
	health       map[string]*sessionHealth
	closed       bool
}

type sessionHealth struct {
	sampledAt time.Time
	bytes     uint64
	rate      float64
	hasRate   bool
}

// NewSessionPool creates an empty pool with the given dispatch policy.
func NewSessionPool(policy DispatchPolicy) *SessionPool {
	return &SessionPool{
		policy:       policy,
		activeCounts: make(map[string]*int64),
		health:       make(map[string]*sessionHealth),
	}
}

// AddSession registers a session. Duplicate IDs and nil sessions are ignored.
func (p *SessionPool) AddSession(s Session) {
	if s == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	for _, existing := range p.sessions {
		if existing.ID() == s.ID() {
			return
		}
	}
	p.sessions = append(p.sessions, s)
	if _, ok := p.activeCounts[s.ID()]; !ok {
		var count int64
		p.activeCounts[s.ID()] = &count
	}
	var received atomic.Uint64
	p.received.Store(s.ID(), &received)
	if _, ok := p.health[s.ID()]; !ok {
		p.health[s.ID()] = &sessionHealth{}
	}
	logging.Infof("[pool] session %s added; active sessions: %d", s.ID(), len(p.sessions))
}

// ObserveReceived records bytes received from a session. The scheduler uses
// this passive signal to avoid assigning new streams to decayed rooms.
func (p *SessionPool) ObserveReceived(id string, n int) {
	if n <= 0 {
		return
	}
	if value, ok := p.received.Load(id); ok {
		value.(*atomic.Uint64).Add(uint64(n))
	}
}

// StreamRef identifies a TCP stream whose transport was lost.
type StreamRef struct{ RuleID, StreamID string }

// RemoveSession excludes a failed path and returns its streams for local close.
// Callers use a unique session ID for every connection incarnation.
func (p *SessionPool) RemoveSession(id string) []StreamRef {
	p.mu.Lock()
	defer p.mu.Unlock()
	kept := p.sessions[:0]
	for _, s := range p.sessions {
		if s.ID() != id {
			kept = append(kept, s)
		}
	}
	p.sessions = kept
	delete(p.activeCounts, id)
	p.received.Delete(id)
	delete(p.health, id)
	var refs []StreamRef
	p.streamMap.Range(func(key, value any) bool {
		if value.(Session).ID() == id {
			p.streamMap.Delete(key)
			rule, stream, _ := strings.Cut(key.(string), "\x00")
			refs = append(refs, StreamRef{rule, stream})
		}
		return true
	})
	return refs
}

func (p *SessionPool) HasSession(id string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, s := range p.sessions {
		if s.ID() == id {
			return true
		}
	}
	return false
}

// SessionCount returns the number of registered sessions.
func (p *SessionPool) SessionCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.sessions)
}

// BindStream pins an existing stream to a session. The controlled side uses it
// so replies leave through the session the CONNECT arrived on.
func (p *SessionPool) BindStream(ruleID, streamID string, s Session) {
	if ruleID == "" || streamID == "" || s == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	count := p.activeCounts[s.ID()]
	if p.closed || count == nil {
		return
	}
	if _, loaded := p.streamMap.LoadOrStore(streamKey(ruleID, streamID), s); !loaded {
		atomic.AddInt64(count, 1)
	}
}

// SelectSession returns the session bound to the stream, choosing and binding
// one according to the dispatch policy when the stream is new.
func (p *SessionPool) SelectSession(ruleID, streamID string) (Session, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	key := streamKey(ruleID, streamID)
	if existing, ok := p.streamMap.Load(key); ok {
		return existing.(Session), nil
	}

	if len(p.sessions) == 0 {
		return nil, errors.New("no active sessions available in pool")
	}

	var chosen Session
	switch p.policy {
	case PolicyHealthAware:
		maxScore := -1.0
		for _, s := range p.sessions {
			var active int64
			if ptr := p.activeCounts[s.ID()]; ptr != nil {
				active = atomic.LoadInt64(ptr)
			}
			score := p.healthScore(s.ID(), active)
			if score > maxScore {
				maxScore = score
				chosen = s
			}
		}
	case PolicyStreamLeastLoaded:
		minCount := int64(-1)
		for _, s := range p.sessions {
			var count int64
			if ptr := p.activeCounts[s.ID()]; ptr != nil {
				count = atomic.LoadInt64(ptr)
			}
			if minCount < 0 || count < minCount {
				minCount = count
				chosen = s
			}
		}
	default:
		idx := p.rrIndex.Add(1) - 1
		chosen = p.sessions[idx%uint64(len(p.sessions))]
	}

	if actual, loaded := p.streamMap.LoadOrStore(key, chosen); loaded {
		return actual.(Session), nil
	}
	if count := p.activeCounts[chosen.ID()]; count != nil {
		atomic.AddInt64(count, 1)
	}
	return chosen, nil
}

// ReleaseStream drops the stream binding once the stream has finished. It
// implements StreamReleaser, so Tunnel calls it after the last frame of a
// stream (including a rejected CONNECT) has been sent.
func (p *SessionPool) ReleaseStream(ruleID, streamID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	val, loaded := p.streamMap.LoadAndDelete(streamKey(ruleID, streamID))
	if !loaded {
		return
	}
	if count := p.activeCounts[val.(Session).ID()]; count != nil {
		atomic.AddInt64(count, -1)
	}
}

// SendFrame implements FrameSender by decoding the routing keys from the wire
// bytes. Tunnel uses SendRoutedFrame instead, which skips the decode.
func (p *SessionPool) SendFrame(msg []byte) error {
	frame := decodeFrameForTunnel(msg)
	if frame == nil {
		return errors.New("pool: frame is not a port mapping message")
	}
	return p.SendRoutedFrame(frame.RuleID, frame.StreamID, frame.Type, msg)
}

// SendRoutedFrame implements RoutedFrameSender: a CONNECT picks and binds the
// session for its stream, every later frame follows that binding. The binding
// lives until the tunnel calls ReleaseStream, because DATA_ACK frames for the
// peer's data still have to be sent after this side's FIN.
func (p *SessionPool) SendRoutedFrame(ruleID, streamID string, frameType gvpb.FrameType, msg []byte) error {
	var session Session
	if frameType == gvpb.TypeConnect {
		var err error
		session, err = p.SelectSession(ruleID, streamID)
		if err != nil {
			return err
		}
	} else {
		bound, ok := p.streamMap.Load(streamKey(ruleID, streamID))
		if !ok {
			return errors.New("stream transport no longer exists")
		}
		session = bound.(Session)
	}
	return session.SendFrame(msg)
}

// Close terminates all sessions and empties the pool.
func (p *SessionPool) Close() error {
	p.mu.Lock()
	p.closed = true
	sessions := p.sessions
	p.sessions = nil
	p.activeCounts = make(map[string]*int64)
	p.health = make(map[string]*sessionHealth)
	p.received.Clear()
	p.streamMap.Clear()
	p.mu.Unlock()
	var errs []error
	for _, s := range sessions {
		if err := s.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (p *SessionPool) healthScore(id string, active int64) float64 {
	now := time.Now()
	health := p.health[id]
	if health == nil {
		health = &sessionHealth{}
		p.health[id] = health
	}
	var total uint64
	if value, ok := p.received.Load(id); ok {
		total = value.(*atomic.Uint64).Load()
	}
	if !health.sampledAt.IsZero() {
		elapsed := now.Sub(health.sampledAt).Seconds()
		if elapsed > 0 {
			instant := float64(total-health.bytes) / elapsed
			const alpha = 0.35
			if health.hasRate {
				health.rate = alpha*instant + (1-alpha)*health.rate
			} else {
				health.rate = instant
				health.hasRate = true
			}
		}
	}
	health.bytes = total
	health.sampledAt = now

	capacity := health.rate
	if !health.hasRate {
		// Unknown idle sessions are assumed to be fresh and useful.
		capacity = 8 * 1024 * 1024
	} else if capacity < 64*1024 {
		capacity = 64 * 1024
	}
	// Capacity matters more than perfect stream balance: when one relay room is
	// already slow, concentrating a new stream on a healthy room is better than
	// spreading every stream across a known-bad allocation.
	return capacity / (1 + float64(active)*0.10)
}

// AdaptiveSessionPool keeps a single session on a direct connection and, once
// a relayed connection is detected, asks expandFn to grow the pool to
// targetSessions. Without expandFn it only records the detected mode.
type AdaptiveSessionPool struct {
	mu             sync.Mutex
	pool           *SessionPool
	targetSessions int
	mode           string
	expanding      bool
	expandFn       func(target int) error
}

// NewAdaptiveSessionPool constructs an adaptive pool controller. A target of
// zero or less selects the single-session default.
func NewAdaptiveSessionPool(targetSessions int, policy DispatchPolicy, expandFn func(target int) error) *AdaptiveSessionPool {
	if targetSessions <= 0 {
		targetSessions = 1
	}
	return &AdaptiveSessionPool{
		pool:           NewSessionPool(policy),
		targetSessions: targetSessions,
		expandFn:       expandFn,
	}
}

// Pool returns the underlying SessionPool.
func (a *AdaptiveSessionPool) Pool() *SessionPool { return a.pool }

// CurrentMode returns the last detected candidate pair mode ("direct",
// "relay", or "" before detection).
func (a *AdaptiveSessionPool) CurrentMode() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.mode
}

// OnModeDetected reacts to the selected ICE candidate pair mode.
func (a *AdaptiveSessionPool) OnModeDetected(mode string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.mode = mode

	switch mode {
	case "direct":
		logging.Infof("[adaptive-pool] direct connection active; single session maintained")
	case "relay":
		switch {
		case a.targetSessions <= 1:
			logging.Infof("[adaptive-pool] relay connection active; pooling disabled (sessions=1)")
		case a.expandFn == nil:
			logging.Infof("[adaptive-pool] relay connection active; continuing with %d session(s)", a.pool.SessionCount())
		case a.expanding:
		default:
			a.expanding = true
			logging.Infof("[adaptive-pool] relay connection detected; expanding pool to %d sessions", a.targetSessions)
			go func() {
				if err := a.expandFn(a.targetSessions); err != nil {
					logging.Errorf("[adaptive-pool] expansion error: %v", err)
				}
			}()
		}
	}
}

// Close terminates every pooled session.
func (a *AdaptiveSessionPool) Close() error { return a.pool.Close() }

// SendFrame implements FrameSender by routing through the underlying pool.
func (a *AdaptiveSessionPool) SendFrame(msg []byte) error { return a.pool.SendFrame(msg) }

// SendRoutedFrame implements RoutedFrameSender through the underlying pool.
func (a *AdaptiveSessionPool) SendRoutedFrame(ruleID, streamID string, frameType gvpb.FrameType, msg []byte) error {
	return a.pool.SendRoutedFrame(ruleID, streamID, frameType, msg)
}

// ReleaseStream implements StreamReleaser through the underlying pool.
func (a *AdaptiveSessionPool) ReleaseStream(ruleID, streamID string) {
	a.pool.ReleaseStream(ruleID, streamID)
}
