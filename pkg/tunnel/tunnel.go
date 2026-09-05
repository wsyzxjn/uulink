// Package tunnel implements symmetric TCP port forwarding over the UU Remote
// port mapping channel.
//
// A rule declares a listener on this device and a target reachable by the
// peer. Incoming CONNECT frames carry their own target address, so either side
// can initiate a mapping without the peer pre-registering that rule.
package tunnel

import (
	crand "crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/wsyzxjn/uulink/pkg/logging"
	"github.com/wsyzxjn/uulink/pkg/proto/gvpb"
)

// FrameSender sends a Message-wrapped PortMappingFrame to the remote peer.
type FrameSender interface {
	SendFrame(msg []byte) error
}

// Rule describes one local listener and the target reachable by the peer.
type Rule struct {
	ID         string
	LocalHost  string
	LocalPort  int
	TargetHost string
	TargetPort int
}

// SessionID is the port mapping session used by the captured protocol.
const SessionID = "1"

const connectTimeout = 10 * time.Second

const (
	maxFrameIDLength = 20
	maxTargetHostLen = 253
	remoteLogLimit   = time.Second
)

// SecurityPolicy defines inbound dial restrictions for CONNECT frames.
//
// Loopback services are intentionally trusted. A local proxy listening on
// loopback can still reach non-loopback networks; use AllowedPorts to narrow
// the services exposed through a tunnel.
type SecurityPolicy struct {
	AllowLAN     bool
	AllowedPorts map[int]bool // nil allows all ports; an empty map allows none
}

// ValidateTarget checks whether target host and port are permitted.
func (p SecurityPolicy) ValidateTarget(host string, port int) error {
	if port <= 0 || port > 65535 {
		return fmt.Errorf("invalid port %d", port)
	}
	if !isValidTargetHost(host) {
		return fmt.Errorf("invalid target host")
	}
	if !p.AllowLAN && !isLoopbackHost(host) {
		return fmt.Errorf("non-loopback target host is blocked by default (enable -allow-lan to permit)")
	}
	if p.AllowedPorts != nil && !p.AllowedPorts[port] {
		return fmt.Errorf("target port %d is not in allowed ports whitelist", port)
	}
	return nil
}

// ParseAllowedPorts parses a comma-separated list of ports or port ranges.
// Examples: "8080", "22,80,443", "8000-8010,9000"
func ParseAllowedPorts(s string) (map[int]bool, error) {
	raw := s
	s = strings.TrimSpace(raw)
	if s == "" {
		if raw != "" {
			return nil, fmt.Errorf("port specification is empty")
		}
		return nil, nil
	}
	ports := make(map[int]bool)
	parts := strings.SplitSeq(s, ",")
	for part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("empty port entry")
		}
		if strings.Contains(part, "-") {
			rangeParts := strings.SplitN(part, "-", 2)
			startStr := strings.TrimSpace(rangeParts[0])
			endStr := strings.TrimSpace(rangeParts[1])
			start, err1 := strconv.Atoi(startStr)
			end, err2 := strconv.Atoi(endStr)
			if err1 != nil || err2 != nil || start <= 0 || end > 65535 || start > end {
				return nil, fmt.Errorf("invalid port range %q", part)
			}
			for p := start; p <= end; p++ {
				ports[p] = true
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil || p <= 0 || p > 65535 {
				return nil, fmt.Errorf("invalid port %q", part)
			}
			ports[p] = true
		}
	}
	return ports, nil
}

// PortPair describes a matched local port and remote target port.
type PortPair struct {
	LocalPort  int
	RemotePort int
}

// ParsePortRange parses either a single port ("8080") or a range ("9000-9010").
func ParsePortRange(s string) (start, end int, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, 0, fmt.Errorf("port is empty")
	}
	if strings.Contains(s, "-") {
		parts := strings.SplitN(s, "-", 2)
		startStr := strings.TrimSpace(parts[0])
		endStr := strings.TrimSpace(parts[1])
		start, err1 := strconv.Atoi(startStr)
		end, err2 := strconv.Atoi(endStr)
		if err1 != nil || err2 != nil || start <= 0 || end > 65535 || start > end {
			return 0, 0, fmt.Errorf("invalid port range %q", s)
		}
		return start, end, nil
	}
	p, err := strconv.Atoi(s)
	if err != nil || p <= 0 || p > 65535 {
		return 0, 0, fmt.Errorf("invalid port %q", s)
	}
	return p, p, nil
}

// ExpandPortRange takes local and remote port specifications (single ports or ranges)
// and expands them into matching 1-to-1 port pairs.
// Examples:
//
//	"8080", "8080" -> [{8080, 8080}]
//	"9000-9005", "8000-8005" -> [{9000, 8000}, {9001, 8001}, ...]
func ExpandPortRange(localSpec, remoteSpec string) ([]PortPair, error) {
	localStart, localEnd, err := ParsePortRange(localSpec)
	if err != nil {
		return nil, fmt.Errorf("local port: %w", err)
	}
	remoteStart, remoteEnd, err := ParsePortRange(remoteSpec)
	if err != nil {
		return nil, fmt.Errorf("remote port: %w", err)
	}

	localCount := localEnd - localStart + 1
	remoteCount := remoteEnd - remoteStart + 1
	if localCount != remoteCount {
		return nil, fmt.Errorf("local range has %d ports (%s) but remote range has %d ports (%s); ranges must be equal in length",
			localCount, localSpec, remoteCount, remoteSpec)
	}

	pairs := make([]PortPair, localCount)
	for i := range localCount {
		pairs[i] = PortPair{
			LocalPort:  localStart + i,
			RemotePort: remoteStart + i,
		}
	}
	return pairs, nil
}

// ParsePortMappingSpec parses a "LOCAL_SPEC:REMOTE_SPEC" mapping string into port pairs.
// Examples:
//
//	"8080:8080"
//	"9000-9005:8000-8005"
func ParsePortMappingSpec(spec string) ([]PortPair, error) {
	spec = strings.TrimSpace(spec)
	parts := strings.Split(spec, ":")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid mapping spec %q, want LOCAL_PORT:REMOTE_PORT or LOCAL_RANGE:REMOTE_RANGE", spec)
	}
	return ExpandPortRange(parts[0], parts[1])
}

func isValidTargetHost(host string) bool {
	if host == "" || len(host) > maxTargetHostLen {
		return false
	}
	for i := 0; i < len(host); i++ {
		c := host[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.', c == '-', c == ':', c == '[', c == ']':
		default:
			return false
		}
	}
	return true
}

func isValidFrameID(id string) bool {
	if id == "" || len(id) > maxFrameIDLength {
		return false
	}
	for i := 0; i < len(id); i++ {
		if id[i] < '0' || id[i] > '9' {
			return false
		}
	}
	return true
}

func isLoopbackHost(host string) bool {
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	h = strings.Trim(h, "[]")
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	if ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// GenerateRuleID generates an 8-byte numeric rule identifier string.
func GenerateRuleID() string {
	var b [8]byte
	if _, err := crand.Read(b[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	v := binary.BigEndian.Uint64(b[:]) & ((1 << 63) - 1)
	if v == 0 {
		v = uint64(time.Now().UnixNano())
	}
	return strconv.FormatUint(v, 10)
}

const defaultMaxInFlight = 128

// Tunnel manages one or more local mapping rules and all PM streams.
type Tunnel struct {
	sender         FrameSender
	rules          map[string]Rule
	listeners      map[string]net.Listener
	streams        sync.Map // stream key -> *stream
	nextIDs        map[string]uint32
	mu             sync.Mutex
	done           chan struct{}
	securityPolicy SecurityPolicy
	remoteLogTime  time.Time
	remoteLogged   bool
	maxInFlight    int
}

type stream struct {
	ruleID         string
	id             string
	conn           net.Conn
	tunnel         *Tunnel
	ready          chan struct{}
	ackSem         chan struct{}
	closed         chan struct{}
	closeOnce      sync.Once
	once           sync.Once
	mu             sync.Mutex
	localFinSent   bool
	remoteFinRecv  bool
	halfCloseTimer *time.Timer
}

// NewTunnel creates a tunnel for one rule.
func NewTunnel(rule Rule, sender FrameSender) *Tunnel {
	return NewTunnelWithRules([]Rule{rule}, sender)
}

// NewTunnelWithRules creates a tunnel for multiple local listeners. Rule IDs
// must be unique within one process.
func NewTunnelWithRules(rules []Rule, sender FrameSender) *Tunnel {
	t := &Tunnel{
		sender:    sender,
		rules:     make(map[string]Rule, len(rules)),
		listeners: make(map[string]net.Listener, len(rules)),
		nextIDs:   make(map[string]uint32, len(rules)),
		done:      make(chan struct{}),
	}
	for _, rule := range rules {
		if rule.ID == "" {
			continue
		}
		if _, exists := t.rules[rule.ID]; exists {
			logging.Debugf("[tunnel] duplicate rule ID %s ignored", rule.ID)
			continue
		}
		if rule.LocalHost == "" {
			rule.LocalHost = "127.0.0.1"
		}
		t.rules[rule.ID] = rule
	}
	return t
}

// Start begins listening for every configured rule.
func (t *Tunnel) Start() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.rules) == 0 {
		return fmt.Errorf("no port mapping rules configured")
	}

	ids := make([]string, 0, len(t.rules))
	for id := range t.rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	opened := make(map[string]net.Listener, len(ids))
	for _, id := range ids {
		rule := t.rules[id]
		addr := net.JoinHostPort(rule.LocalHost, strconv.Itoa(rule.LocalPort))
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			for _, openedLn := range opened {
				openedLn.Close()
			}
			return fmt.Errorf("listen %s: %w", addr, err)
		}
		opened[id] = ln
	}

	for id, ln := range opened {
		rule := t.rules[id]
		t.listeners[id] = ln
		logging.Infof("[tunnel] rule %s: listening on %s -> peer-target %s:%d",
			rule.ID, ln.Addr().String(), rule.TargetHost, rule.TargetPort)
		go t.acceptLoop(rule, ln)
	}
	return nil
}

// ListenerAddr returns the bound address for a started rule.
func (t *Tunnel) ListenerAddr(ruleID string) (net.Addr, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	ln, ok := t.listeners[ruleID]
	if !ok {
		return nil, fmt.Errorf("rule %s has no listener", ruleID)
	}
	return ln.Addr(), nil
}

var readBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32768)
		return &b
	},
}

func configureTCPConn(conn net.Conn) {
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
		_ = tcpConn.SetNoDelay(true)
	}
}

// SetMaxInFlight configures the maximum unacknowledged DATA frames allowed in flight
// per stream before pausing reads from the local connection. Pass 0 for default (128).
// Pass a negative value to disable flow control.
func (t *Tunnel) SetMaxInFlight(n int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.maxInFlight = n
}

// MaxInFlight returns the configured maximum in-flight DATA frames per stream.
func (t *Tunnel) MaxInFlight() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.maxInFlight
}

func (t *Tunnel) effectiveMaxInFlight() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.maxInFlight < 0 {
		return 0
	}
	if t.maxInFlight == 0 {
		return defaultMaxInFlight
	}
	return t.maxInFlight
}

func (t *Tunnel) newStream(ruleID, streamID string, conn net.Conn) *stream {
	s := &stream{
		ruleID: ruleID,
		id:     streamID,
		conn:   conn,
		tunnel: t,
		ready:  make(chan struct{}),
		closed: make(chan struct{}),
	}
	if limit := t.effectiveMaxInFlight(); limit > 0 {
		s.ackSem = make(chan struct{}, limit)
	}
	return s
}

// SetSecurityPolicy configures inbound connection restrictions.
func (t *Tunnel) SetSecurityPolicy(policy SecurityPolicy) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.securityPolicy = policy
}

// SecurityPolicy returns the active security policy.
func (t *Tunnel) SecurityPolicy() SecurityPolicy {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.securityPolicy
}

// Stop closes all listeners and active streams.
func (t *Tunnel) Stop() {
	t.mu.Lock()
	select {
	case <-t.done:
		t.mu.Unlock()
		return
	default:
		close(t.done)
	}
	listeners := make([]net.Listener, 0, len(t.listeners))
	for _, ln := range t.listeners {
		listeners = append(listeners, ln)
	}
	t.mu.Unlock()

	for _, ln := range listeners {
		ln.Close()
	}
	t.streams.Range(func(_, v any) bool {
		v.(*stream).close()
		return true
	})
}

func (t *Tunnel) acceptLoop(rule Rule, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-t.done:
				return
			default:
				logging.Errorf("[tunnel] rule %s accept error: %v", rule.ID, err)
				continue
			}
		}

		configureTCPConn(conn)
		streamID := t.nextStreamID(rule.ID)
		s := t.newStream(rule.ID, streamID, conn)
		t.streams.Store(streamKey(rule.ID, streamID), s)
		msg, err := newConnectMsg(rule.ID, streamID, rule.TargetHost, rule.TargetPort)
		if err != nil {
			logging.Errorf("[tunnel] build connect error: %v", err)
			t.closeStream(rule.ID, streamID, false)
			continue
		}
		if err := t.sender.SendFrame(msg); err != nil {
			logging.Errorf("[tunnel] send connect error: %v", err)
			t.closeStream(rule.ID, streamID, false)
			continue
		}
		// Hedged dual-send: send duplicate CONNECT after 10ms to eliminate handshake loss penalty on WAN
		go func(connectMsg []byte, st *stream) {
			select {
			case <-time.After(10 * time.Millisecond):
			case <-st.ready:
				return
			case <-st.closed:
				return
			case <-t.done:
				return
			}
			select {
			case <-st.ready:
				return
			case <-st.closed:
				return
			case <-t.done:
				return
			default:
				_ = t.sender.SendFrame(connectMsg)
			}
		}(msg, s)
		go s.readLoop()
	}
}

// HandleMessage processes a protobuf wire-format Message from the remote peer.
func (t *Tunnel) HandleMessage(data []byte) {
	frame := decodeFrameForTunnel(data)
	if frame == nil {
		return
	}
	if !isValidFrameID(frame.RuleID) || !isValidFrameID(frame.StreamID) {
		return
	}

	key := streamKey(frame.RuleID, frame.StreamID)
	v, streamExists := t.streams.Load(key)

	switch frame.Type {
	case gvpb.TypeConnect:
		if streamExists {
			return
		}
		t.handleConnect(frame)

	case gvpb.TypeSynAck:
		if !streamExists {
			return
		}
		s := v.(*stream)
		var ack struct {
			OK      bool `json:"ok"`
			Version int  `json:"version"`
		}
		if err := json.Unmarshal(frame.Payload, &ack); err == nil && !ack.OK {
			t.closeStream(frame.RuleID, frame.StreamID, false)
			s.markReady()
			return
		}
		s.markReady()

	case gvpb.TypeData:
		if !streamExists {
			return
		}
		s := v.(*stream)
		if _, err := s.conn.Write(frame.Payload); err != nil {
			logging.Errorf("[tunnel] local write error: %v", err)
			t.closeStream(frame.RuleID, frame.StreamID, true)
			return
		}
		t.sendBuiltMsg(newACKMsg(frame.RuleID, frame.StreamID))

	case gvpb.TypeDataAck:
		if streamExists {
			s := v.(*stream)
			s.onACK()
		}

	case gvpb.TypeFin:
		if !streamExists {
			return
		}
		s := v.(*stream)
		s.handleRemoteFIN()

	default:
		logging.Debugf("[tunnel] unknown frame type ignored")
	}
}

func (t *Tunnel) handleConnect(frame *gvpb.PortMappingFrame) {
	var target struct {
		TargetHost string `json:"target_host"`
		TargetPort int    `json:"target_port"`
		Version    int    `json:"version"`
	}
	if err := json.Unmarshal(frame.Payload, &target); err != nil {
		if t.allowRemoteLog() {
			logging.Warnf("[tunnel] connect payload parse error: %v", err)
		}
		t.sendBuiltMsg(newSynAckMsg(frame.RuleID, frame.StreamID, false))
		return
	}
	if target.TargetHost == "" || target.TargetPort <= 0 {
		if t.allowRemoteLog() {
			logging.Warnf("[tunnel] connect payload missing target for rule %s", frame.RuleID)
		}
		t.sendBuiltMsg(newSynAckMsg(frame.RuleID, frame.StreamID, false))
		return
	}

	t.mu.Lock()
	policy := t.securityPolicy
	t.mu.Unlock()

	if err := policy.ValidateTarget(target.TargetHost, target.TargetPort); err != nil {
		if t.allowRemoteLog() {
			logging.Warnf("[tunnel] rule %s stream %s: connect target=%q port=%d rejected by security policy: %v",
				frame.RuleID, frame.StreamID, target.TargetHost, target.TargetPort, err)
		}
		t.sendBuiltMsg(newSynAckMsg(frame.RuleID, frame.StreamID, false))
		return
	}

	addr := net.JoinHostPort(target.TargetHost, strconv.Itoa(target.TargetPort))
	conn, err := net.DialTimeout("tcp", addr, connectTimeout)
	if err != nil {
		if t.allowRemoteLog() {
			logging.Warnf("[tunnel] connect target=%q error: %v", target.TargetHost, err)
		}
		t.sendBuiltMsg(newSynAckMsg(frame.RuleID, frame.StreamID, false))
		return
	}

	configureTCPConn(conn)
	s := t.newStream(frame.RuleID, frame.StreamID, conn)
	t.streams.Store(streamKey(frame.RuleID, frame.StreamID), s)
	synAckMsg, synAckErr := newSynAckMsg(frame.RuleID, frame.StreamID, true)
	t.sendBuiltMsg(synAckMsg, synAckErr)
	s.markReady()
	logging.Debugf("[tunnel] stream connected: rule=%s stream=%s target=%q", frame.RuleID, frame.StreamID, target.TargetHost)
	if synAckErr == nil {
		// Hedged dual-send: send duplicate SYN_ACK after 10ms
		go func(msg []byte, st *stream) {
			select {
			case <-time.After(10 * time.Millisecond):
			case <-st.closed:
				return
			case <-t.done:
				return
			}
			select {
			case <-st.closed:
				return
			case <-t.done:
				return
			default:
				t.sendBuiltMsg(msg, nil)
			}
		}(synAckMsg, s)
	}
	go s.readLoop()
}

func (t *Tunnel) allowRemoteLog() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	if t.remoteLogTime.IsZero() || now.Sub(t.remoteLogTime) >= remoteLogLimit {
		t.remoteLogTime = now
		t.remoteLogged = false
	}
	if t.remoteLogged {
		return false
	}
	t.remoteLogged = true
	return true
}

func (t *Tunnel) nextStreamID(ruleID string) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.nextIDs[ruleID]++
	return strconv.FormatUint(uint64(t.nextIDs[ruleID]), 10)
}

func (t *Tunnel) sendFIN(ruleID, streamID string) {
	msg, err := newFINMsg(ruleID, streamID)
	t.sendBuiltMsg(msg, err)
	if err == nil {
		go func(finMsg []byte) {
			time.Sleep(10 * time.Millisecond)
			t.sendBuiltMsg(finMsg, nil)
		}(msg)
	}
}

func (t *Tunnel) sendBuiltMsg(msg []byte, err error) {
	if err != nil {
		logging.Errorf("[tunnel] build message error: %v", err)
		return
	}
	if err := t.sender.SendFrame(msg); err != nil {
		logging.Errorf("[tunnel] send message error: %v", err)
	}
}

func (t *Tunnel) closeStream(ruleID, streamID string, sendFin bool) {
	key := streamKey(ruleID, streamID)
	if v, ok := t.streams.Load(key); ok {
		s := v.(*stream)
		s.close()
		t.streams.Delete(key)
		if sendFin {
			t.sendFIN(ruleID, streamID)
		}
	}
}

func (s *stream) onACK() {
	if s.ackSem != nil {
		select {
		case <-s.ackSem:
		default:
		}
	}
}

func (s *stream) close() {
	s.closeOnce.Do(func() {
		close(s.closed)
		s.markReady()
		s.mu.Lock()
		if s.halfCloseTimer != nil {
			s.halfCloseTimer.Stop()
		}
		s.mu.Unlock()
		if s.conn != nil {
			_ = s.conn.Close()
		}
	})
}

func (s *stream) armHalfCloseTimeout() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.halfCloseTimer != nil {
		s.halfCloseTimer.Stop()
	}
	s.halfCloseTimer = time.AfterFunc(60*time.Second, func() {
		s.close()
		s.tunnel.streams.Delete(streamKey(s.ruleID, s.id))
	})
}

func (s *stream) handleLocalEOF() {
	s.mu.Lock()
	if s.localFinSent {
		s.mu.Unlock()
		return
	}
	s.localFinSent = true
	bothClosed := s.remoteFinRecv
	s.mu.Unlock()

	s.tunnel.sendFIN(s.ruleID, s.id)

	if bothClosed {
		s.close()
		s.tunnel.streams.Delete(streamKey(s.ruleID, s.id))
	} else {
		s.armHalfCloseTimeout()
	}
}

func (s *stream) handleRemoteFIN() {
	s.mu.Lock()
	if s.remoteFinRecv {
		s.mu.Unlock()
		return
	}
	s.remoteFinRecv = true
	bothClosed := s.localFinSent
	s.mu.Unlock()

	logging.Debugf("[tunnel] stream remote fin: rule=%s stream=%s (bothClosed=%v)", s.ruleID, s.id, bothClosed)

	if bothClosed {
		s.close()
		s.tunnel.streams.Delete(streamKey(s.ruleID, s.id))
	} else {
		if tcpConn, ok := s.conn.(interface{ CloseWrite() error }); ok {
			_ = tcpConn.CloseWrite()
		}
		s.armHalfCloseTimeout()
	}
}

func (s *stream) readLoop() {
	<-s.ready
	select {
	case <-s.closed:
		return
	default:
	}

	pBuf := readBufPool.Get().(*[]byte)
	buf := *pBuf
	defer func() {
		readBufPool.Put(pBuf)
		s.handleLocalEOF()
	}()

	for {
		n, err := s.conn.Read(buf)
		if n > 0 {
			if s.ackSem != nil {
				select {
				case s.ackSem <- struct{}{}:
				case <-s.closed:
					return
				case <-s.tunnel.done:
					return
				}
			}

			payload := make([]byte, n)
			copy(payload, buf[:n])
			msg, msgErr := newDataMsg(s.ruleID, s.id, payload)
			if msgErr != nil {
				logging.Errorf("[tunnel] build data error: %v", msgErr)
				return
			}
			if err := s.tunnel.sender.SendFrame(msg); err != nil {
				logging.Errorf("[tunnel] send data error: %v", err)
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				logging.Debugf("[tunnel] local stream ended: %v", err)
			}
			return
		}
	}
}

func (s *stream) markReady() {
	s.once.Do(func() {
		close(s.ready)
	})
}

// DecodeFrameForTunnel decodes a wire-format frame into a PortMappingFrame.
func DecodeFrameForTunnel(data []byte) *gvpb.PortMappingFrame {
	return decodeFrameForTunnel(data)
}

func decodeFrameForTunnel(data []byte) *gvpb.PortMappingFrame {
	if msg, err := decodeMsg(data); err == nil && msg.PortMappingFrame != nil {
		return msg.PortMappingFrame
	}

	var jmsg struct {
		Frame struct {
			SessionID string `json:"sessionId"`
			RuleID    string `json:"ruleId"`
			StreamID  string `json:"streamId"`
			Type      string `json:"type"`
			Payload   []byte `json:"payload"`
		} `json:"portMappingFrame"`
	}
	if err := json.Unmarshal(data, &jmsg); err != nil {
		logging.Debugf("[tunnel] message parse error: %v", err)
		return nil
	}
	if jmsg.Frame.RuleID == "" && jmsg.Frame.StreamID == "" {
		return nil
	}
	return &gvpb.PortMappingFrame{
		SessionID: jmsg.Frame.SessionID,
		RuleID:    jmsg.Frame.RuleID,
		StreamID:  jmsg.Frame.StreamID,
		Type:      gvpb.FrameType(jmsg.Frame.Type),
		Payload:   jmsg.Frame.Payload,
	}
}

func streamKey(ruleID, streamID string) string {
	return ruleID + "\x00" + streamID
}

// CloseStreams aborts only streams whose session has failed. Data from an old
// TCP stream must never be moved to a replacement transport without replay.
func (t *Tunnel) CloseStreams(refs []StreamRef) {
	for _, ref := range refs {
		t.closeStream(ref.RuleID, ref.StreamID, false)
	}
}
