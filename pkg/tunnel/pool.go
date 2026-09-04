package tunnel

import (
	"context"
	"container/heap"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/user/uulink/pkg/logging"
	"github.com/user/uulink/pkg/proto/gvpb"
)

// Session represents an independent WebRTC DataChannel connection backed
// by its own distinct TURN allocation.
type Session interface {
	ID() string
	SendFrame(msg []byte) error
	Close() error
}

// DispatchPolicy dictates how outgoing streams or data frames are distributed
// across the sessions in a pool.
type DispatchPolicy int

const (
	// PolicyStreamRoundRobin assigns each new TCP stream (CONNECT) to the next session.
	// All subsequent DATA and CLOSE frames for that stream stay on the chosen session.
	// This guarantees strict in-order delivery without packet reordering overhead.
	PolicyStreamRoundRobin DispatchPolicy = iota

	// PolicyStreamLeastLoaded assigns each new stream to the session with the fewest
	// active streams.
	PolicyStreamLeastLoaded

	// PolicyChunkStriping stripes data chunks of each stream across all active sessions
	// using sequence numbers, and reassembles them in-order on the receiving peer.
	PolicyChunkStriping
)

// SimpleSession wraps a FrameSender and an ID string into a Session.
type SimpleSession struct {
	id     string
	sender FrameSender
	closer func() error
}

// NewSimpleSession constructs a Session from a FrameSender.
func NewSimpleSession(id string, sender FrameSender, closer func() error) *SimpleSession {
	return &SimpleSession{
		id:     id,
		sender: sender,
		closer: closer,
	}
}

// ID returns the session identifier.
func (s *SimpleSession) ID() string {
	return s.id
}

// SendFrame sends a protobuf wire-format message through the session.
func (s *SimpleSession) SendFrame(msg []byte) error {
	return s.sender.SendFrame(msg)
}

// Close terminates the session.
func (s *SimpleSession) Close() error {
	if s.closer != nil {
		return s.closer()
	}
	return nil
}

// SessionPool manages multiple concurrent sessions and multiplexes traffic
// to overcome single-allocation TURN relay rate limits (e.g. 12 Mbps cap).
type SessionPool struct {
	mu           sync.RWMutex
	sessions     []Session
	policy       DispatchPolicy
	rrIndex      uint64
	streamMap    sync.Map // streamKey (string) -> Session
	activeCounts map[string]*int64
	reorderPool  sync.Map // streamKey (string) -> *ReorderBuffer
}

// NewSessionPool creates a session pool with the specified dispatch policy.
func NewSessionPool(policy DispatchPolicy) *SessionPool {
	return &SessionPool{
		policy:       policy,
		activeCounts: make(map[string]*int64),
	}
}

// AddSession registers a new session into the pool.
func (p *SessionPool) AddSession(s Session) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, existing := range p.sessions {
		if existing.ID() == s.ID() {
			return
		}
	}
	p.sessions = append(p.sessions, s)
	if _, ok := p.activeCounts[s.ID()]; !ok {
		var cnt int64
		p.activeCounts[s.ID()] = &cnt
	}
	logging.Infof("[pool] session %s added; active sessions: %d", s.ID(), len(p.sessions))
}

// RemoveSession unregisters a session from the pool.
func (p *SessionPool) RemoveSession(sessionID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	idx := -1
	for i, s := range p.sessions {
		if s.ID() == sessionID {
			idx = i
			break
		}
	}
	if idx >= 0 {
		p.sessions = append(p.sessions[:idx], p.sessions[idx+1:]...)
		delete(p.activeCounts, sessionID)
		logging.Infof("[pool] session %s removed; active sessions: %d", sessionID, len(p.sessions))
	}
}

// SessionCount returns the current number of active sessions in the pool.
func (p *SessionPool) SessionCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.sessions)
}

// Sessions returns a snapshot of the current sessions.
func (p *SessionPool) Sessions() []Session {
	p.mu.RLock()
	defer p.mu.RUnlock()
	copied := make([]Session, len(p.sessions))
	copy(copied, p.sessions)
	return copied
}

// SelectSession chooses an appropriate session for a new or existing stream.
func (p *SessionPool) SelectSession(ruleID, streamID string) (Session, error) {
	key := streamKey(ruleID, streamID)
	if existing, ok := p.streamMap.Load(key); ok {
		return existing.(Session), nil
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	n := len(p.sessions)
	if n == 0 {
		return nil, errors.New("no active sessions available in pool")
	}

	var chosen Session
	switch p.policy {
	case PolicyStreamLeastLoaded:
		minCount := int64(1<<62 - 1)
		for _, s := range p.sessions {
			cntPtr := p.activeCounts[s.ID()]
			cnt := int64(0)
			if cntPtr != nil {
				cnt = atomic.LoadInt64(cntPtr)
			}
			if cnt < minCount {
				minCount = cnt
				chosen = s
			}
		}
	case PolicyStreamRoundRobin, PolicyChunkStriping:
		fallthrough
	default:
		idx := atomic.AddUint64(&p.rrIndex, 1) - 1
		chosen = p.sessions[idx%uint64(n)]
	}

	if chosen != nil {
		p.streamMap.Store(key, chosen)
		if cntPtr := p.activeCounts[chosen.ID()]; cntPtr != nil {
			atomic.AddInt64(cntPtr, 1)
		}
	}
	return chosen, nil
}

// ReleaseStream cleans up the binding and counters when a stream terminates.
func (p *SessionPool) ReleaseStream(ruleID, streamID string) {
	key := streamKey(ruleID, streamID)
	val, loaded := p.streamMap.LoadAndDelete(key)
	if loaded {
		s := val.(Session)
		p.mu.RLock()
		if cntPtr := p.activeCounts[s.ID()]; cntPtr != nil {
			atomic.AddInt64(cntPtr, -1)
		}
		p.mu.RUnlock()
	}
	p.reorderPool.Delete(key)
}

// SendForStream delivers a frame through the assigned session of the stream.
func (p *SessionPool) SendForStream(ruleID, streamID string, msg []byte) error {
	session, err := p.SelectSession(ruleID, streamID)
	if err != nil {
		return err
	}
	return session.SendFrame(msg)
}

// NextChunkSession returns the next round-robin session for packet-level striping.
func (p *SessionPool) NextChunkSession() (Session, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	n := len(p.sessions)
	if n == 0 {
		return nil, errors.New("no active sessions in pool")
	}
	idx := atomic.AddUint64(&p.rrIndex, 1) - 1
	return p.sessions[idx%uint64(n)], nil
}

// Close terminates all sessions managed by the pool.
func (p *SessionPool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	var errs []error
	for _, s := range p.sessions {
		if err := s.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	p.sessions = nil
	p.activeCounts = make(map[string]*int64)
	if len(errs) > 0 {
		return fmt.Errorf("close sessions: %v", errs)
	}
	return nil
}

// StripedChunkHeaderPrefix identifies a data chunk containing a 4-byte sequence number.
const StripedChunkMagic uint32 = 0x53545250 // "STRP"

// EncodeStripedPayload wraps a raw payload with a sequence number.
func EncodeStripedPayload(seq uint32, payload []byte) []byte {
	buf := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint32(buf[0:4], StripedChunkMagic)
	binary.BigEndian.PutUint32(buf[4:8], seq)
	copy(buf[8:], payload)
	return buf
}

// DecodeStripedPayload parses a sequenced payload. Returns (seq, payload, isStriped).
func DecodeStripedPayload(data []byte) (uint32, []byte, bool) {
	if len(data) >= 8 && binary.BigEndian.Uint32(data[0:4]) == StripedChunkMagic {
		seq := binary.BigEndian.Uint32(data[4:8])
		return seq, data[8:], true
	}
	return 0, data, false
}

// chunkItem is used in the min-heap priority queue for in-order packet reassembly.
type chunkItem struct {
	seq     uint32
	payload []byte
}

type chunkPriorityQueue []chunkItem

func (pq chunkPriorityQueue) Len() int           { return len(pq) }
func (pq chunkPriorityQueue) Less(i, j int) bool { return pq[i].seq < pq[j].seq }
func (pq chunkPriorityQueue) Swap(i, j int)      { pq[i], pq[j] = pq[j], pq[i] }
func (pq *chunkPriorityQueue) Push(x any)        { *pq = append(*pq, x.(chunkItem)) }
func (pq *chunkPriorityQueue) Pop() any {
	old := *pq
	n := len(old)
	item := old[n-1]
	*pq = old[0 : n-1]
	return item
}

// ReorderBuffer handles out-of-order chunk arrivals across striped sessions
// and returns ready sequential payloads.
type ReorderBuffer struct {
	mu       sync.Mutex
	expected uint32
	queue    chunkPriorityQueue
}

// NewReorderBuffer creates a reassembly buffer starting at sequence 0.
func NewReorderBuffer() *ReorderBuffer {
	rb := &ReorderBuffer{
		expected: 0,
	}
	heap.Init(&rb.queue)
	return rb
}

// Insert inserts a chunk and returns all consecutive available chunks in order.
func (rb *ReorderBuffer) Insert(seq uint32, payload []byte) [][]byte {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	// If old duplicate, ignore
	if seq < rb.expected {
		return nil
	}

	heap.Push(&rb.queue, chunkItem{seq: seq, payload: payload})

	var ready [][]byte
	for rb.queue.Len() > 0 {
		top := rb.queue[0]
		if top.seq == rb.expected {
			heap.Pop(&rb.queue)
			ready = append(ready, top.payload)
			rb.expected++
		} else {
			break
		}
	}
	return ready
}

// PoolTunnel wraps a standard Tunnel with a SessionPool to deliver multipath forwarding.
type PoolTunnel struct {
	*Tunnel
	pool *SessionPool
}

// NewPoolTunnel constructs a tunnel wired to a session pool.
func NewPoolTunnel(rules []Rule, pool *SessionPool) *PoolTunnel {
	pt := &PoolTunnel{
		pool: pool,
	}
	// The tunnel's sender routes through pool dispatch
	pt.Tunnel = NewTunnelWithRules(rules, &poolSenderAdapter{pool: pool})
	return pt
}

type poolSenderAdapter struct {
	pool *SessionPool
}

func (a *poolSenderAdapter) SendFrame(msg []byte) error {
	frame := decodeFrameForTunnel(msg)
	if frame == nil {
		// Fallback to next session if raw frame
		s, err := a.pool.NextChunkSession()
		if err != nil {
			return err
		}
		return s.SendFrame(msg)
	}

	// Route based on stream binding
	err := a.pool.SendForStream(frame.RuleID, frame.StreamID, msg)
	if frame.Type == gvpb.TypeFin {
		a.pool.ReleaseStream(frame.RuleID, frame.StreamID)
	}
	return err
}


// AdaptiveSessionPool wraps a SessionPool to implement the adaptive pooling strategy:
// - Direct P2P mode (mode == "direct"): single session is maintained (unthrottled, zero overhead).
// - Relay mode (mode == "relay"): automatically activates multi-session pooling up to TargetSessions (default: 4, ~48 Mbps).
type AdaptiveSessionPool struct {
	mu             sync.Mutex
	pool           *SessionPool
	targetSessions int
	mode           string
	isExpanding    int32
	expandFn       func(ctx context.Context, target int) error
	cancel         context.CancelFunc
}

// NewAdaptiveSessionPool constructs an adaptive pool controller.
func NewAdaptiveSessionPool(targetSessions int, policy DispatchPolicy, expandFn func(ctx context.Context, target int) error) *AdaptiveSessionPool {
	if targetSessions <= 0 {
		targetSessions = 4
	}
	return &AdaptiveSessionPool{
		pool:           NewSessionPool(policy),
		targetSessions: targetSessions,
		expandFn:       expandFn,
	}
}

// TargetSessions returns the configured target session count for relay mode.
func (a *AdaptiveSessionPool) TargetSessions() int {
	return a.targetSessions
}

// Pool returns the underlying SessionPool.
func (a *AdaptiveSessionPool) Pool() *SessionPool {
	return a.pool
}

// CurrentMode returns the detected candidate pair mode ("direct", "relay", or "").
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

	if mode == "direct" {
		logging.Infof("[adaptive-pool] direct P2P connection active; single session maintained (unlimited bandwidth)")
		return
	}

	if mode == "relay" {
		if a.targetSessions <= 1 {
			logging.Infof("[adaptive-pool] relay mode active; single session configured (sessions=%d)", a.targetSessions)
			return
		}

		if !atomic.CompareAndSwapInt32(&a.isExpanding, 0, 1) {
			return
		}

		logging.Infof("[adaptive-pool] relay mode detected; activating multi-session pool (target: %d sessions, ~%d Mbps bandwidth pool)",
			a.targetSessions, a.targetSessions*12)

		if a.expandFn != nil {
			ctx, cancel := context.WithCancel(context.Background())
			a.cancel = cancel
			go func() {
				if err := a.expandFn(ctx, a.targetSessions); err != nil {
					logging.Errorf("[adaptive-pool] expansion error: %v", err)
				}
			}()
		}
	}
}

// Close stops the adaptive pool and cancels any ongoing expansion.
func (a *AdaptiveSessionPool) Close() error {
	a.mu.Lock()
	if a.cancel != nil {
		a.cancel()
	}
	a.mu.Unlock()
	return a.pool.Close()
}

// SendFrame implements FrameSender to route outgoing tunnel messages through the pool.
func (a *AdaptiveSessionPool) SendFrame(msg []byte) error {
	adapter := &poolSenderAdapter{pool: a.pool}
	return adapter.SendFrame(msg)
}
