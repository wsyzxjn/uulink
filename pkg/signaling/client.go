// Package signaling implements the UU Remote socket.io signaling client (EIO=4).
//
// Wire format (captured from official client):
//   - Text frames: EIO packets (0=open, 2=ping, 3=pong, 4=message)
//   - socket.io packets inside EIO '4': 0=connect, 2=event, 3=ack,
//     5=binary_event, 6=binary_ack
//   - Binary attachments: sent as separate WebSocket BINARY frames whose
//     payload is 0x04 (EIO message marker) + raw content (gzip SDP or protobuf)
//   - BINARY_EVENT format: "45<count>-[<ack-id>][json with _placeholders]"
package signaling

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// EIO4 packet types
const (
	eioOpen    = '0'
	eioClose   = '1'
	eioPing    = '2'
	eioPong    = '3'
	eioMessage = '4'
)

// socket.io packet types (prefixed after EIO message '4')
const (
	sioConnect      = '0'
	sioDisconnect   = '1'
	sioEvent        = '2'
	sioAck          = '3'
	sioConnectError = '4'
	sioBinaryEvent  = '5'
	sioBinaryAck    = '6'
)

// Event carries a decoded socket.io event with its (spliced) arguments.
type Event struct {
	Name string
	Args []json.RawMessage
}

// RoomInfo is the subset of the room_info ack needed by a controlled peer.
type RoomInfo struct {
	RoomID   string
	ClientID string
	DeviceID string
}

// Client is a socket.io EIO=4 client over WebSocket with binary attachment support.
type Client struct {
	conn         *websocket.Conn
	mu           sync.Mutex
	pingInterval time.Duration
	pingTimeout  time.Duration
	done         chan struct{}
	readyCh      chan struct{} // closed on namespace connect confirmation
	handlers     map[string]func(*Event)
	hmu          sync.RWMutex
	ackHandlers  map[int]func([]json.RawMessage)
	ackCounter   int
	amu          sync.Mutex

	// Pending binary events waiting for attachments
	pendingBinaryEvent *pendingBinaryEvent
}

type pendingBinaryEvent struct {
	packet    []byte // the socket.io packet after EIO '4'
	needCount int
	acks      [][]byte
}

// ConnectConfig holds connection parameters for the signaling gateway.
type ConnectConfig struct {
	GatewayURL  string // wss://sig-3207-z2.nrd.nie.163.com/
	NRDAuth     string // X-NRD-AUTH token from room/join
	ReconnKey   string // X-NRD-RECONN-KEY for reconnection
	Controlling bool   // true = controller, false = controlled
	Version     string // streamer_version, default V4.5.3
}

// Connect establishes a socket.io connection to the signaling gateway.
func Connect(cfg *ConnectConfig) (*Client, error) {
	version := cfg.Version
	if version == "" {
		version = "V4.5.3"
	}

	controlling := "0"
	if cfg.Controlling {
		controlling = "1"
	}

	u := cfg.GatewayURL
	if !strings.HasSuffix(u, "/") {
		u += "/"
	}
	ts := fmt.Sprintf("%d", time.Now().UnixMilli())
	wsURL := u + "socket.io/?EIO=4&transport=websocket&t=" + ts

	header := http.Header{}
	header.Set("X-NRD-AUTH", cfg.NRDAuth)
	header.Set("X-NRD-CONTROLLING", controlling)
	if cfg.ReconnKey != "" {
		header.Set("X-NRD-RECONN-KEY", cfg.ReconnKey)
	}
	header.Set("streamer_flag", `{"sdp_flags":{"gzip_sdp":true}}`)
	header.Set("streamer_version", version)
	header.Set("User-Agent", "WebSocket++/0.8.2")

	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}

	conn, _, err := dialer.Dial(wsURL, header)
	if err != nil {
		return nil, fmt.Errorf("websocket dial: %w", err)
	}

	c := &Client{
		conn:        conn,
		done:        make(chan struct{}),
		readyCh:     make(chan struct{}),
		handlers:    make(map[string]func(*Event)),
		ackHandlers: make(map[int]func([]json.RawMessage)),
	}

	// Read the EIO open packet
	_, msg, err := conn.ReadMessage()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read open: %w", err)
	}

	if len(msg) == 0 || msg[0] != eioOpen {
		conn.Close()
		return nil, fmt.Errorf("expected EIO open, got: %s", string(msg))
	}

	var openData struct {
		SID          string `json:"sid"`
		PingInterval int    `json:"pingInterval"`
		PingTimeout  int    `json:"pingTimeout"`
	}
	if err := json.Unmarshal(msg[1:], &openData); err != nil {
		conn.Close()
		return nil, fmt.Errorf("parse open: %w", err)
	}

	c.pingInterval = time.Duration(openData.PingInterval) * time.Millisecond
	c.pingTimeout = time.Duration(openData.PingTimeout) * time.Millisecond

	log.Printf("[signaling] connected, sid=%s, pingInterval=%v", openData.SID, c.pingInterval)

	go c.readLoop()
	go c.pingLoop()

	// Complete the socket.io namespace connection (server responds 40{"sid":...})
	if err := c.send("40"); err != nil {
		conn.Close()
		return nil, fmt.Errorf("send namespace connect: %w", err)
	}

	return c, nil
}

// On registers a handler for a socket.io event. Attachments are spliced
// into the args before dispatch.
func (c *Client) On(event string, handler func(*Event)) {
	c.hmu.Lock()
	defer c.hmu.Unlock()
	c.handlers[event] = handler
}

// Emit sends a plain socket.io event.
func (c *Client) Emit(event string, args ...any) error {
	payload := make([]any, 0, 1+len(args))
	payload = append(payload, event)
	payload = append(payload, args...)
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	packet := string([]byte{eioMessage, sioEvent}) + string(data)
	return c.send(packet)
}

// EmitWithAck sends an event and registers a callback for the server's ack.
// Returns the ack id.
func (c *Client) EmitWithAck(event string, args any, onAck func([]json.RawMessage)) (int, error) {
	c.amu.Lock()
	c.ackCounter++
	ackID := c.ackCounter
	if onAck != nil {
		c.ackHandlers[ackID] = onAck
	}
	c.amu.Unlock()

	payload := []any{event, args}
	data, err := json.Marshal(payload)
	if err != nil {
		return 0, fmt.Errorf("marshal event: %w", err)
	}
	packet := string([]byte{eioMessage, sioEvent}) + strconv.Itoa(ackID) + string(data)
	if err := c.send(packet); err != nil {
		return 0, err
	}
	return ackID, nil
}

// EmitWithAckNoArgs sends an event with an ack request and no payload args.
func (c *Client) EmitWithAckNoArgs(event string, onAck func([]json.RawMessage)) (int, error) {
	c.amu.Lock()
	c.ackCounter++
	ackID := c.ackCounter
	if onAck != nil {
		c.ackHandlers[ackID] = onAck
	}
	c.amu.Unlock()

	data, err := json.Marshal([]string{event})
	if err != nil {
		return 0, fmt.Errorf("marshal event: %w", err)
	}
	packet := string([]byte{eioMessage, sioEvent}) + strconv.Itoa(ackID) + string(data)
	if err := c.send(packet); err != nil {
		return 0, err
	}
	return ackID, nil
}

// RequestRoomInfo asks the signaling gateway for this connection's room metadata.
func (c *Client) RequestRoomInfo() (*RoomInfo, error) {
	ch := make(chan *RoomInfo, 1)
	_, err := c.EmitWithAckNoArgs("room_info", func(arr []json.RawMessage) {
		if len(arr) == 0 {
			ch <- nil
			return
		}
		var raw struct {
			RoomID string `json:"room_id"`
			You    struct {
				ClientID string `json:"client_id"`
				DeviceID string `json:"device_id"`
			} `json:"you"`
		}
		if err := json.Unmarshal(arr[0], &raw); err != nil {
			log.Printf("[signaling] room_info parse error: %v", err)
			ch <- nil
			return
		}
		ch <- &RoomInfo{
			RoomID:   raw.RoomID,
			ClientID: raw.You.ClientID,
			DeviceID: raw.You.DeviceID,
		}
	})
	if err != nil {
		return nil, fmt.Errorf("send room_info: %w", err)
	}

	select {
	case info := <-ch:
		if info == nil || info.ClientID == "" {
			return nil, fmt.Errorf("room_info did not contain client_id")
		}
		return info, nil
	case <-c.Done():
		return nil, fmt.Errorf("signaling closed while waiting for room_info")
	case <-time.After(5 * time.Second):
		return nil, fmt.Errorf("timeout waiting for room_info")
	}
}

// RefreshReconnectKey performs the controller-side refresh_reconnect_key
// handshake required before sending control. The key is returned for future
// reconnection use, but callers must not log it.
func (c *Client) RefreshReconnectKey() (string, error) {
	type refreshResult struct {
		key string
		err error
	}
	ch := make(chan refreshResult, 1)

	_, err := c.EmitWithAckNoArgs("refresh_reconnect_key", func(arr []json.RawMessage) {
		var result refreshResult
		defer func() { ch <- result }()

		if len(arr) < 2 {
			result.err = fmt.Errorf("malformed refresh_reconnect_key ack")
			return
		}

		var status string
		if err := json.Unmarshal(arr[0], &status); err != nil {
			result.err = fmt.Errorf("parse refresh status: %w", err)
			return
		}
		if status != "success" {
			result.err = fmt.Errorf("refresh_reconnect_key rejected with status %q", status)
			return
		}

		var data struct {
			ReconnectKey string `json:"reconnect_key"`
		}
		if err := json.Unmarshal(arr[1], &data); err != nil {
			result.err = fmt.Errorf("parse refresh_reconnect_key ack: %w", err)
			return
		}
		if data.ReconnectKey == "" {
			result.err = fmt.Errorf("refresh_reconnect_key ack did not contain a key")
			return
		}
		result.key = data.ReconnectKey
	})
	if err != nil {
		return "", fmt.Errorf("send refresh_reconnect_key: %w", err)
	}

	select {
	case result := <-ch:
		if result.err != nil {
			return "", result.err
		}
		log.Printf("[signaling] refresh_reconnect_key succeeded (key length %d)", len(result.key))
		return result.key, nil
	case <-c.Done():
		return "", fmt.Errorf("signaling closed while waiting for refresh_reconnect_key")
	case <-time.After(5 * time.Second):
		return "", fmt.Errorf("timeout waiting for refresh_reconnect_key")
	}
}

// EmitBinary sends a socket.io BINARY_EVENT with one binary attachment.
// The JSON must contain {"_placeholder":true,"num":0} where the attachment goes;
// this helper handles the wire format: text frame "451-[json]" + binary frame
// 0x04+content.
func (c *Client) EmitBinary(event string, args any, attachment []byte) error {
	return c.EmitBinaryWithAck(event, args, attachment, 0, nil)
}

// EmitBinaryWithAck is EmitBinary with an ack id (0 = no ack).
func (c *Client) EmitBinaryWithAck(event string, args any, attachment []byte, ackID int, onAck func([]json.RawMessage)) error {
	return c.EmitBinaryWithAcks(event, args, attachment, []int{ackID}, onAck)
}

// EmitBinaryWithAcks sends a binary event using the first ack ID and optionally
// listens for additional ack IDs. UU's control handshake can return a reconnect
// key ack followed by the actual control result under the next ack ID.
func (c *Client) EmitBinaryWithAcks(event string, args any, attachment []byte, ackIDs []int, onAck func([]json.RawMessage)) error {
	if len(ackIDs) == 0 {
		return fmt.Errorf("at least one ack id is required")
	}
	if onAck != nil {
		c.amu.Lock()
		for _, ackID := range ackIDs {
			c.ackHandlers[ackID] = onAck
		}
		c.amu.Unlock()
	}

	ackID := ackIDs[0]

	payload := []any{event, args}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}

	prefix := string([]byte{eioMessage, sioBinaryEvent}) + "1-"
	if ackID > 0 {
		prefix += strconv.Itoa(ackID)
	}
	packet := prefix + string(data)

	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.conn.WriteMessage(websocket.TextMessage, []byte(packet)); err != nil {
		return fmt.Errorf("send binary event text: %w", err)
	}
	// Attachment: 0x04 prefix + content
	frame := append([]byte{0x04}, attachment...)
	if err := c.conn.WriteMessage(websocket.BinaryMessage, frame); err != nil {
		return fmt.Errorf("send attachment: %w", err)
	}
	return nil
}

// NamespaceConnected returns a channel closed when the socket.io namespace
// connection is confirmed by the server (40{"sid":...} response).
func (c *Client) NamespaceConnected() <-chan struct{} {
	return c.readyCh
}

// Close shuts down the connection.
func (c *Client) Close() error {
	select {
	case <-c.done:
	default:
		close(c.done)
	}
	return c.conn.Close()
}

// Done returns a channel that's closed when the connection ends.
func (c *Client) Done() <-chan struct{} {
	return c.done
}

func (c *Client) send(msg string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn.WriteMessage(websocket.TextMessage, []byte(msg))
}

func (c *Client) readLoop() {
	defer func() {
		select {
		case <-c.done:
		default:
			close(c.done)
		}
	}()

	for {
		msgType, msg, err := c.conn.ReadMessage()
		if err != nil {
			if !websocket.IsCloseError(err, websocket.CloseNormalClosure) {
				log.Printf("[signaling] read error: %v", err)
			}
			return
		}

		if msgType == websocket.BinaryMessage {
			c.handleBinaryFrame(msg)
			continue
		}

		if len(msg) == 0 {
			continue
		}

		switch msg[0] {
		case eioPing:
			_ = c.send(string([]byte{eioPong}))
		case eioPong:
			// server pong, ignore
		case eioClose:
			log.Printf("[signaling] server closed connection")
			return
		case eioMessage:
			c.handleSIOPacket(msg[1:])
		}
	}
}

// handleBinaryFrame processes an incoming WebSocket binary frame (attachment).
// Payload = 0x04 prefix + content.
func (c *Client) handleBinaryFrame(msg []byte) {
	c.amu.Lock()
	pending := c.pendingBinaryEvent
	c.pendingBinaryEvent = nil
	c.amu.Unlock()

	if pending == nil {
		log.Printf("[signaling] unexpected binary frame (%d bytes)", len(msg))
		return
	}

	content := msg
	if len(content) > 0 && content[0] == 0x04 {
		content = content[1:]
	}
	pending.acks = append(pending.acks, content)

	if len(pending.acks) < pending.needCount {
		// wait for more attachments
		c.amu.Lock()
		c.pendingBinaryEvent = pending
		c.amu.Unlock()
		return
	}

	c.dispatchBinaryEvent(pending.packet, pending.acks)
}

func (c *Client) dispatchBinaryEvent(packet []byte, attachments [][]byte) {
	// packet = "5<count>-[<ackid>][json]"
	rest := packet[1:] // skip '5'
	if idx := bytes.IndexByte(rest, '-'); idx >= 0 {
		rest = rest[idx+1:]
	}
	// Skip ack id if present (digits before '[')
	for len(rest) > 0 && rest[0] >= '0' && rest[0] <= '9' {
		rest = rest[1:]
	}

	var arr []json.RawMessage
	if err := json.Unmarshal(rest, &arr); err != nil {
		log.Printf("[signaling] parse binary event error: %v (packet: %s)", err, string(packet)[:min(len(packet), 100)])
		return
	}
	if len(arr) == 0 {
		return
	}

	var event string
	if err := json.Unmarshal(arr[0], &event); err != nil {
		return
	}

	// Splice attachments into placeholders
	for i, arg := range arr[1:] {
		arr[i+1] = spliceAttachment(arg, attachments)
	}

	ev := &Event{Name: event, Args: arr[1:]}
	c.dispatchEvent(ev)
}

// spliceAttachment replaces {"_placeholder":true,"num":N} in raw JSON
// with the actual attachment content (as JSON string for gzip SDP,
// or raw bytes object). UU uses base64-in-JSON for gzip_sdp on receive
// is NOT used - the placeholder is replaced by the decompressed string
// by the official client; we pass raw and let handlers decode.
func spliceAttachment(raw json.RawMessage, attachments [][]byte) json.RawMessage {
	var probe map[string]any
	if err := json.Unmarshal(raw, &probe); err != nil {
		return raw
	}
	if ph, ok := probe["_placeholder"].(bool); ok && ph {
		num := 0
		if n, ok := probe["num"].(float64); ok {
			num = int(n)
		}
		if num < len(attachments) {
			// Try gzip decode; fall back to raw
			content := attachments[num]
			if s, err := gunzipIfCompressed(content); err == nil {
				quoted, _ := json.Marshal(s)
				return quoted
			}
			// Not gzip: return as base64 string to keep JSON valid
			quoted, _ := json.Marshal(content)
			return quoted
		}
	}
	// Recurse into nested objects
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err == nil {
		changed := false
		for k, v := range obj {
			nv := spliceAttachment(v, attachments)
			if string(nv) != string(v) {
				obj[k] = nv
				changed = true
			}
		}
		if changed {
			out, err := json.Marshal(obj)
			if err == nil {
				return out
			}
		}
	}
	return raw
}

func gunzipIfCompressed(data []byte) (string, error) {
	if len(data) < 2 || data[0] != 0x1f || data[1] != 0x8b {
		return "", fmt.Errorf("not gzip")
	}
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	defer r.Close()
	b, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func (c *Client) handleSIOPacket(data []byte) {
	if len(data) == 0 {
		return
	}

	switch data[0] {
	case sioConnect:
		log.Printf("[signaling] namespace connected: %s", string(data[1:]))
		select {
		case <-c.readyCh:
		default:
			close(c.readyCh)
		}
	case sioDisconnect:
		log.Printf("[signaling] namespace disconnected")
	case sioConnectError:
		log.Printf("[signaling] namespace connect error: %s", string(data[1:]))
	case sioEvent:
		c.handleEventPacket(data[1:])
	case sioAck, sioBinaryAck:
		c.handleAckPacket(data[1:])
	case sioBinaryEvent:
		c.handleBinaryEventPacket(data[1:])
	}
}

func (c *Client) handleEventPacket(data []byte) {
	var arr []json.RawMessage
	if err := json.Unmarshal(data, &arr); err != nil {
		log.Printf("[signaling] parse event error: %v", err)
		return
	}
	if len(arr) == 0 {
		return
	}
	var event string
	if err := json.Unmarshal(arr[0], &event); err != nil {
		return
	}
	c.dispatchEvent(&Event{Name: event, Args: arr[1:]})
}

func (c *Client) handleAckPacket(data []byte) {
	// data = "<ackid>[json]"
	rest := data
	ackID := 0
	for len(rest) > 0 && rest[0] >= '0' && rest[0] <= '9' {
		ackID = ackID*10 + int(rest[0]-'0')
		rest = rest[1:]
	}
	if ackID == 0 {
		return
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(rest, &arr); err != nil {
		// ack payload may be a single object
		arr = []json.RawMessage{rest}
	}

	c.amu.Lock()
	handler := c.ackHandlers[ackID]
	delete(c.ackHandlers, ackID)
	c.amu.Unlock()

	if handler != nil {
		handler(arr)
	} else {
		log.Printf("[signaling] unhandled ack %d: %s", ackID, string(rest)[:min(len(rest), 150)])
	}
}

func (c *Client) handleBinaryEventPacket(data []byte) {
	// data = "<count>-[<ackid>][json]"
	rest := data
	count := 0
	for len(rest) > 0 && rest[0] >= '0' && rest[0] <= '9' {
		count = count*10 + int(rest[0]-'0')
		rest = rest[1:]
	}
	if len(rest) == 0 || rest[0] != '-' {
		log.Printf("[signaling] malformed binary event: %s", string(data)[:min(len(data), 80)])
		return
	}
	rest = rest[1:]

	if count == 0 {
		// no attachments - treat as normal event
		c.handleEventPacket(rest)
		return
	}

	c.amu.Lock()
	c.pendingBinaryEvent = &pendingBinaryEvent{
		packet:    append([]byte{sioBinaryEvent}, data...),
		needCount: count,
	}
	c.amu.Unlock()
}

func (c *Client) dispatchEvent(ev *Event) {
	c.hmu.RLock()
	handler, ok := c.handlers[ev.Name]
	c.hmu.RUnlock()

	if ok {
		handler(ev)
	} else {
		log.Printf("[signaling] unhandled event: %s", ev.Name)
	}
}

func (c *Client) pingLoop() {
	ticker := time.NewTicker(c.pingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			if err := c.send(string([]byte{eioPing})); err != nil {
				log.Printf("[signaling] ping error: %v", err)
				return
			}
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
