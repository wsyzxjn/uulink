// Package tunnel implements symmetric TCP port forwarding over the UU Remote
// port mapping channel.
//
// A rule declares a listener on this device and a target reachable by the
// peer. Incoming CONNECT frames carry their own target address, so either side
// can initiate a mapping without the peer pre-registering that rule.
package tunnel

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/user/uulink/pkg/proto/gvpb"
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

// Tunnel manages one or more local mapping rules and all PM streams.
type Tunnel struct {
	sender    FrameSender
	rules     map[string]Rule
	listeners map[string]net.Listener
	streams   sync.Map // stream key -> *stream
	nextIDs   map[string]uint32
	mu        sync.Mutex
	done      chan struct{}
}

type stream struct {
	ruleID string
	id     string
	conn   net.Conn
	tunnel *Tunnel
	ready  chan struct{}
	once   sync.Once
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
			log.Printf("[tunnel] duplicate rule ID %s ignored", rule.ID)
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
		log.Printf("[tunnel] rule %s: listening on %s -> peer-target %s:%d",
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
		v.(*stream).conn.Close()
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
				log.Printf("[tunnel] rule %s accept error: %v", rule.ID, err)
				continue
			}
		}

		streamID := t.nextStreamID(rule.ID)
		s := &stream{ruleID: rule.ID, id: streamID, conn: conn, tunnel: t, ready: make(chan struct{})}
		t.streams.Store(streamKey(rule.ID, streamID), s)
		log.Printf("[tunnel] rule %s accepted local connection, streamId=%s", rule.ID, streamID)

		msg, err := newConnectMsg(rule.ID, streamID, rule.TargetHost, rule.TargetPort)
		if err != nil {
			log.Printf("[tunnel] build connect error: %v", err)
			t.closeStream(rule.ID, streamID, false)
			continue
		}
		log.Printf("[tunnel] CONNECT wire: %x", truncateBytesForLog(msg))
		if err := t.sender.SendFrame(msg); err != nil {
			log.Printf("[tunnel] send connect error: %v", err)
			t.closeStream(rule.ID, streamID, false)
			continue
		}
		go s.readLoop()
	}
}

// HandleMessage processes a protobuf wire-format Message from the remote peer.
func (t *Tunnel) HandleMessage(data []byte) {
	frame := decodeFrameForTunnel(data)
	if frame == nil {
		log.Printf("[tunnel] message contained no PortMappingFrame: %x", truncateBytesForLog(data))
		return
	}

	log.Printf("[tunnel] inbound PM frame: type=%s rule=%s stream=%s payload=%d bytes",
		frame.Type, frame.RuleID, frame.StreamID, len(frame.Payload))

	key := streamKey(frame.RuleID, frame.StreamID)
	v, streamExists := t.streams.Load(key)

	switch frame.Type {
	case gvpb.TypeConnect:
		if streamExists {
			log.Printf("[tunnel] duplicate CONNECT for rule %s stream %s", frame.RuleID, frame.StreamID)
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
			log.Printf("[tunnel] connect refused for rule %s stream %s", frame.RuleID, frame.StreamID)
			t.closeStream(frame.RuleID, frame.StreamID, false)
			s.markReady()
			return
		}
		s.markReady()
		log.Printf("[tunnel] SYN_ACK received for rule %s stream %s", frame.RuleID, frame.StreamID)

	case gvpb.TypeData:
		if !streamExists {
			return
		}
		s := v.(*stream)
		if _, err := s.conn.Write(frame.Payload); err != nil {
			log.Printf("[tunnel] local write error: %v", err)
			t.closeStream(frame.RuleID, frame.StreamID, true)
			return
		}
		t.sendBuiltMsg(newACKMsg(frame.RuleID, frame.StreamID))

	case gvpb.TypeDataAck:
		// Per-message acknowledgements are currently informational.

	case gvpb.TypeFin:
		if !streamExists {
			return
		}
		t.closeStream(frame.RuleID, frame.StreamID, false)
		log.Printf("[tunnel] remote FIN, rule %s stream %s closed", frame.RuleID, frame.StreamID)

	default:
		log.Printf("[tunnel] unknown frame type %q ignored", frame.Type)
	}
}

func (t *Tunnel) handleConnect(frame *gvpb.PortMappingFrame) {
	var target struct {
		TargetHost string `json:"target_host"`
		TargetPort int    `json:"target_port"`
		Version    int    `json:"version"`
	}
	if err := json.Unmarshal(frame.Payload, &target); err != nil {
		log.Printf("[tunnel] connect payload parse error: %v", err)
		t.sendBuiltMsg(newSynAckMsg(frame.RuleID, frame.StreamID, false))
		return
	}
	if target.TargetHost == "" || target.TargetPort <= 0 {
		log.Printf("[tunnel] connect payload missing target for rule %s", frame.RuleID)
		t.sendBuiltMsg(newSynAckMsg(frame.RuleID, frame.StreamID, false))
		return
	}

	addr := net.JoinHostPort(target.TargetHost, strconv.Itoa(target.TargetPort))
	conn, err := net.DialTimeout("tcp", addr, connectTimeout)
	if err != nil {
		log.Printf("[tunnel] connect target %s error: %v", addr, err)
		t.sendBuiltMsg(newSynAckMsg(frame.RuleID, frame.StreamID, false))
		return
	}

	s := &stream{
		ruleID: frame.RuleID,
		id:     frame.StreamID,
		conn:   conn,
		tunnel: t,
		ready:  make(chan struct{}),
	}
	t.streams.Store(streamKey(frame.RuleID, frame.StreamID), s)
	t.sendBuiltMsg(newSynAckMsg(frame.RuleID, frame.StreamID, true))
	s.markReady()
	log.Printf("[tunnel] connected target %s for rule %s stream %s",
		addr, frame.RuleID, frame.StreamID)
	go s.readLoop()
}

func (t *Tunnel) nextStreamID(ruleID string) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.nextIDs[ruleID]++
	return strconv.FormatUint(uint64(t.nextIDs[ruleID]), 10)
}

func (t *Tunnel) sendFIN(ruleID, streamID string) {
	t.sendBuiltMsg(newFINMsg(ruleID, streamID))
}

func (t *Tunnel) sendBuiltMsg(msg []byte, err error) {
	if err != nil {
		log.Printf("[tunnel] build message error: %v", err)
		return
	}
	if err := t.sender.SendFrame(msg); err != nil {
		log.Printf("[tunnel] send message error: %v", err)
	}
}

func (t *Tunnel) closeStream(ruleID, streamID string, sendFin bool) {
	key := streamKey(ruleID, streamID)
	if v, ok := t.streams.Load(key); ok {
		s := v.(*stream)
		s.conn.Close()
		t.streams.Delete(key)
		s.markReady()
		if sendFin {
			t.sendFIN(ruleID, streamID)
		}
	}
}

func (s *stream) readLoop() {
	<-s.ready
	defer func() {
		s.conn.Close()
		s.tunnel.streams.Delete(streamKey(s.ruleID, s.id))
		s.tunnel.sendFIN(s.ruleID, s.id)
	}()

	buf := make([]byte, 16384)
	for {
		n, err := s.conn.Read(buf)
		if n > 0 {
			payload := make([]byte, n)
			copy(payload, buf[:n])
			msg, msgErr := newDataMsg(s.ruleID, s.id, payload)
			if msgErr != nil {
				log.Printf("[tunnel] build data error: %v", msgErr)
				return
			}
			log.Printf("[tunnel] DATA wire: %x", truncateBytesForLog(msg))
			if err := s.tunnel.sender.SendFrame(msg); err != nil {
				log.Printf("[tunnel] send data error: %v", err)
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("[tunnel] local read error: %v", err)
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
		log.Printf("[tunnel] message parse error: %v", err)
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

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func truncateBytesForLog(b []byte) []byte {
	if len(b) > 256 {
		return b[:256]
	}
	return b
}
