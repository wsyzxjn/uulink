// Package peer manages the WebRTC peer connection for UU Remote.
//
// Controller flow (reverse-engineered from official client):
//  1. socket.io connect (done by signaling.Client)
//  2. emit "control" event with GvPb_ConnectOptions protobuf attachment
//     -> server ACK returns client_id, ice_id, iceServers (STUN/TURN + credentials)
//  3. create PeerConnection with those ICE servers + data channels
//  4. emit "soac" offer with gzip(SDP) binary attachment
//  5. emit "soac" candidate events during ICE gathering
//  6. receive "soac" answer (gzip attachment) + candidates
package peer

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pion/webrtc/v4"
	"github.com/wsyzxjn/uulink/pkg/logging"
	"github.com/wsyzxjn/uulink/pkg/signaling"
)

// Data channel labels used by UU Remote (from libstreamer.dylib).
const (
	LabelStreamer = "STREAMER_DATA_CHANNEL"
	LabelControl  = "CONTROL_DATA_CHANNEL"
	LabelFile     = "FILE_DATA_CHANNEL"
	LabelBinary   = "BINARY_DATA_CHANNEL"
	LabelText     = "TEXT_DATA_CHANNEL"
)

// connectOptionsHex is the GvPb_ConnectOptions protobuf captured from the
// official 4.38.0 macOS client (contains device_id aeawqa5txeafoxl4 = this
// machine and version 4.38.0). Replayed verbatim.
const connectOptionsHex = "080110ffffffffffffffffff011a190802100620012a0608802810c01632003801408087a70e583c220c0878100218801e20f0102801220c0878100218801e20f0102803220c0878100118801e20f0102801220c0878100118801e20f0102803320808802810c01618783a0608802810c01640044a106165617771613574786561666f786c3450015a10080610021801200230023802400248016206342e33382e30"

// ConnectOptionsHex exposes the captured protobuf for external use.
const ConnectOptionsHex = connectOptionsHex

// Controlled peers do not receive the controller's control-ack ICE list.
// These are the public STUN servers observed in that ack.
var controlledSTUNServers = []webrtc.ICEServer{
	{URLs: []string{"stun:61.174.14.99:2580"}},
	{URLs: []string{"stun:61.153.100.69:2480"}},
	{URLs: []string{"stun:61.153.100.70:2480"}},
}

// ControlAckData is the server's response to the control event.
type ControlAckData struct {
	Code       int    `json:"code"`
	ClientID   string `json:"client_id"`
	IceID      string `json:"ice_id"`
	ForceRelay bool   `json:"force_relay"`
	ICEServers []struct {
		URLs       string `json:"urls"`
		Username   string `json:"username,omitempty"`
		Credential string `json:"credential,omitempty"`
	} `json:"iceServers"`
}

// WebRTCICEServers converts the ack's iceServers to pion format.
func (a *ControlAckData) WebRTCICEServers() []webrtc.ICEServer {
	var out []webrtc.ICEServer
	for _, s := range a.ICEServers {
		out = append(out, webrtc.ICEServer{
			URLs:       []string{s.URLs},
			Username:   s.Username,
			Credential: s.Credential,
		})
	}
	return out
}

// Config for creating a controller Peer.
type Config struct {
	Signal        *signaling.Client
	DeviceID      string // our device id (for streamer_data)
	AppControlID  string
	Passive       bool          // skip signaling control handshake (room-file controller)
	TransportMode TransportMode // controller transport policy: auto or relay
	// SDPOfferFile, when non-empty, makes the controller write its WebRTC
	// offer to this file and wait for SDPAnswerFile instead of using soac.
	SDPOfferFile  string
	SDPAnswerFile string
	OnBinaryData  func(data []byte)
	OnSignalData  func(data []byte) // pb channel messages (port mapping frames)
	OnICEState    func(state string)
}

// Peer manages the UU Remote WebRTC session as controller.
type Peer struct {
	sig                    *signaling.Client
	appControlID           string
	iceID                  string
	clientID               string
	routingClientID        string
	ack                    *ControlAckData
	sdpOfferFile           string
	sdpAnswerFile          string
	transportMode          TransportMode
	effectiveTransportMode TransportMode
	pc                     *webrtc.PeerConnection
	binaryDC               *webrtc.DataChannel
	controlDC              *webrtc.DataChannel
	textDC                 *webrtc.DataChannel
	onTextMessage          func([]byte)
	pendingText            [][]byte
	textOpen               chan struct{}
	textOpenOnce           sync.Once
	fileDC                 *webrtc.DataChannel
	mu                     sync.Mutex
	onBinaryData           func([]byte)
	onSignalData           func([]byte)
	onBinaryOpen           func()
	onFileOpen             func()
	onICEConnected         func()
	onModeChange           func(string)
	controlEchoOnce        sync.Once
	remoteCandidates       []string
	ackCh                  chan *ControlAckData
	soacMu                 sync.Mutex
	controlledReady        chan struct{}
	pendingSOAC            []*signaling.Event
	remoteDescSet          bool
	pendingCandidates      []webrtc.ICECandidateInit
	selectedPair           *webrtc.ICECandidatePair
	statsDone              chan struct{}
	statsRunning           bool
	restartRequested       chan struct{}
	restartOnce            sync.Once
}

type soacEvent struct {
	ClientID string `json:"client_id"`
	Data     struct {
		AppControlID string `json:"app_control_id"`
		GzipSDP      string `json:"gzip_sdp"`
		SDP          string `json:"sdp"`
		Type         string `json:"type"`
		IceID        string `json:"ice_id"`
		Candidate    struct {
			Candidate     string `json:"candidate"`
			SDPMLineIndex uint16 `json:"sdpMLineIndex"`
			SDPMid        string `json:"sdpMid"`
		} `json:"candidate"`
	} `json:"data"`
}

// NewController creates a controller peer and initiates the control handshake.
func NewController(cfg *Config) (*Peer, error) {
	appControlID := cfg.AppControlID
	if appControlID == "" {
		var err error
		appControlID, err = randomUUID()
		if err != nil {
			return nil, err
		}
	}

	p := &Peer{
		textOpen:         make(chan struct{}),
		restartRequested: make(chan struct{}),
		sig:              cfg.Signal,
		appControlID:     appControlID,
		sdpOfferFile:     cfg.SDPOfferFile,
		sdpAnswerFile:    cfg.SDPAnswerFile,
		transportMode:    cfg.TransportMode,
		onBinaryData:     cfg.OnBinaryData,
		onSignalData:     cfg.OnSignalData,
		ackCh:            make(chan *ControlAckData, 1),
		statsDone:        make(chan struct{}),
	}

	// Register soac handler before starting
	cfg.Signal.On("soac", p.handleSOAC)

	// Register the pb channel handler (sentProtocolBufferfile / streamerDidReceiveFileData)
	cfg.Signal.On("sentProtocolBufferfile", func(ev *signaling.Event) {})
	cfg.Signal.On("streamerDidReceiveFileData", func(ev *signaling.Event) {
		if p.onSignalData != nil && len(ev.Args) > 0 {
			// args[0] may be the pb JSON string or object
			p.onSignalData(ev.Args[0])
		}
	})

	// The official controller refreshes the reconnect key before its first
	// control event. The signaling gateway rejects control with 100001 without
	// this server-side state update.
	if cfg.Passive {
		// Room-file controller: the signaling token belongs to the guest's
		// controlled-side session, so controller-role events are rejected.
		// Use the controlled-side room-info path instead of the control
		// handshake and let the normal soac exchange carry the WebRTC setup.
		info, err := cfg.Signal.RequestRoomInfo()
		if err != nil {
			return nil, fmt.Errorf("room info: %w", err)
		}
		p.clientID = info.ClientID
		p.routingClientID = info.ClientID
		p.iceID = info.ClientID
		logging.Debugf("[peer] passive controller room info: room_id=%s client_id=%s",
			info.RoomID, info.ClientID)
		return p, nil
	}
	if _, err := cfg.Signal.RefreshReconnectKey(); err != nil {
		return nil, fmt.Errorf("refresh reconnect key: %w", err)
	}

	// Step 1: send control event, wait for ACK
	if err := p.sendControl(cfg.DeviceID); err != nil {
		return nil, fmt.Errorf("send control: %w", err)
	}

	select {
	case ack := <-p.ackCh:
		if ack.Code != 0 {
			return nil, fmt.Errorf("control rejected, code %d", ack.Code)
		}
		p.clientID = ack.ClientID
		p.routingClientID = ack.ClientID
		p.iceID = ack.IceID
		p.ack = ack
		logging.Debugf("[peer] control ack: client_id=%s ice_id=%s force_relay=%v ice_servers=%d",
			ack.ClientID, ack.IceID, ack.ForceRelay, len(ack.ICEServers))
		return p, nil
	case <-cfg.Signal.Done():
		return nil, fmt.Errorf("signaling closed while waiting for control ack")
	}
}

// NewControlled creates a peer that answers a controller's soac offer. It is
// the UULink-side replacement for running the official controlled client.
func NewControlled(cfg *Config) (*Peer, error) {
	p := &Peer{
		textOpen:         make(chan struct{}),
		restartRequested: make(chan struct{}),
		sig:              cfg.Signal,
		onBinaryData:     cfg.OnBinaryData,
		onSignalData:     cfg.OnSignalData,
		controlledReady:  make(chan struct{}),
		statsDone:        make(chan struct{}),
	}

	// A controller can emit its offer immediately after room/create returns,
	// before this process has completed room_info. Cache early offers until the
	// controlled peer knows its signaling client_id.
	cfg.Signal.On("soac", func(ev *signaling.Event) {
		select {
		case <-p.controlledReady:
			p.handleControlledSOAC(ev)
		default:
			p.mu.Lock()
			p.pendingSOAC = append(p.pendingSOAC, ev)
			p.mu.Unlock()
		}
	})
	cfg.Signal.On("streamerDidReceiveFileData", func(ev *signaling.Event) {
		if p.onSignalData != nil && len(ev.Args) > 0 {
			p.onSignalData(ev.Args[0])
		}
	})

	info, err := cfg.Signal.RequestRoomInfo()
	if err != nil {
		return nil, fmt.Errorf("room info: %w", err)
	}
	if _, err := cfg.Signal.RefreshReconnectKey(); err != nil {
		return nil, fmt.Errorf("refresh reconnect key: %w", err)
	}
	p.clientID = info.ClientID
	logging.Debugf("[peer] controlled room info: room_id=%s client_id=%s device_id=%s",
		info.RoomID, info.ClientID, info.DeviceID)

	p.mu.Lock()
	pending := append([]*signaling.Event(nil), p.pendingSOAC...)
	p.pendingSOAC = nil
	p.mu.Unlock()
	close(p.controlledReady)
	for _, ev := range pending {
		p.handleControlledSOAC(ev)
	}
	return p, nil
}

// CapOverride replaces field 11 (capability blob) inside the ConnectOptions
// protobuf. capHex is the hex of the inner 16-byte blob (e.g. "08061002180120023002380240024801").
func CapOverride(capHex string) error {
	pb, err := hex.DecodeString(connectOptionsHex)
	if err != nil {
		return err
	}
	newCap, err := hex.DecodeString(capHex)
	if err != nil {
		return fmt.Errorf("bad cap hex: %w", err)
	}
	// Re-encode the protobuf with field 11 replaced.
	out, err := replacePBBytesField(pb, 11, newCap)
	if err != nil {
		return err
	}
	connectOptionsOverride = hex.EncodeToString(out)
	return nil
}

var connectOptionsOverride string

func replacePBBytesField(pb []byte, fieldNum uint64, value []byte) ([]byte, error) {
	var out []byte
	i := 0
	rd := func() (uint64, error) {
		var v uint64
		var s uint
		for {
			if i >= len(pb) {
				return 0, fmt.Errorf("truncated varint")
			}
			x := pb[i]
			i++
			v |= uint64(x&0x7f) << s
			if x < 0x80 {
				return v, nil
			}
			s += 7
		}
	}
	for i < len(pb) {
		tag, err := rd()
		if err != nil {
			return nil, err
		}
		currentField := tag >> 3
		wireType := tag & 7
		switch wireType {
		case 0:
			v, _ := rd()
			out = append(out, byte(tag))
			var buf []byte
			for v >= 0x80 {
				buf = append(buf, byte(v)|0x80)
				v >>= 7
			}
			out = append(out, append(buf, byte(v))...)
		case 2:
			ln, err := rd()
			if err != nil {
				return nil, err
			}
			payload := pb[i : i+int(ln)]
			i += int(ln)
			if currentField == fieldNum {
				payload = value
				ln = uint64(len(value))
			}
			out = append(out, byte(tag))
			var buf []byte
			for ln >= 0x80 {
				buf = append(buf, byte(ln)|0x80)
				ln >>= 7
			}
			out = append(out, append(buf, byte(ln))...)
			out = append(out, payload...)
		default:
			return nil, fmt.Errorf("unsupported wire type %d", wireType)
		}
	}
	return out, nil
}

// sendControl emits the control event with the ConnectOptions protobuf.
func (p *Peer) sendControl(deviceID string) error {
	hexStr := connectOptionsHex
	if connectOptionsOverride != "" {
		hexStr = connectOptionsOverride
	}
	pb, err := hex.DecodeString(hexStr)
	if err != nil {
		return err
	}
	if deviceID != "" {
		pb, err = replacePBBytesField(pb, 9, []byte(deviceID))
		if err != nil {
			return fmt.Errorf("replace control device id: %w", err)
		}
	}

	streamerData := map[string]any{
		"control_id": p.appControlID,
		"device_capability": map[string]any{
			"display_info":           []any{},
			"video_codec_capability": []any{},
			"ice_id":                 "",
		},
	}
	sdJSON, _ := json.Marshal(streamerData)

	payload := map[string]any{
		"app_control_id": p.appControlID,
		"app_data":       map[string]any{"_placeholder": true, "num": 0},
		"streamer_data":  string(sdJSON),
	}

	return p.sig.EmitBinaryWithAcks("control", payload, pb, []int{3, 4}, func(arr []json.RawMessage) {
		// arr = ["success", {data}]
		if len(arr) < 2 {
			logging.Debugf("[peer] control ack malformed: %v", arr)
			return
		}
		var probe struct {
			ReconnectKey string `json:"reconnect_key"`
		}
		if err := json.Unmarshal(arr[1], &probe); err == nil && probe.ReconnectKey != "" {
			logging.Debugf("[peer] control reconnect key refreshed (key length %d)", len(probe.ReconnectKey))
			return
		}
		var data ControlAckData
		if err := json.Unmarshal(arr[1], &data); err != nil {
			// some acks are ["success", {"reconnect_key":...}] - not our ack
			logging.Debugf("[peer] control ack parse: %v (%s)", err, string(arr[1])[:min(len(string(arr[1])), 100)])
			return
		}
		p.ackCh <- &data
	})
}

// Connect creates the PeerConnection with TURN servers from the control ack
// (or the provided override), creates data channels, sends the SDP offer via soac.
func (p *Peer) Connect(iceServers []webrtc.ICEServer) error {
	if iceServers == nil && p.ack != nil {
		iceServers = p.ack.WebRTCICEServers()
		logging.Debugf("[peer] using %d ICE servers from control ack", len(iceServers))
	}
	serverRequiresRelay := p.ack != nil && p.ack.ForceRelay
	mode := resolveTransportMode(p.transportMode, serverRequiresRelay)
	if mode != TransportAuto && mode != TransportRelay {
		return fmt.Errorf("invalid transport mode %q", mode)
	}
	if mode == TransportRelay && !hasTURNServer(iceServers) {
		return fmt.Errorf("transport relay requires a TURN server but none was supplied")
	}

	p.mu.Lock()
	p.effectiveTransportMode = mode
	p.mu.Unlock()

	rtcCfg := webrtc.Configuration{
		ICEServers:         iceServers,
		ICETransportPolicy: transportICEPolicy(mode),
	}
	logging.Infof("[peer] transport mode=%s server_requires_relay=%v", mode.String(), serverRequiresRelay)

	pc, err := webrtc.NewPeerConnection(rtcCfg)
	if err != nil {
		return fmt.Errorf("new peer connection: %w", err)
	}
	p.mu.Lock()
	p.pc = pc
	p.mu.Unlock()

	pc.OnICECandidate(p.onICECandidate)
	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		logging.Infof("[peer] connection state: %s", state.String())
		p.logConnectionStats(pc, "controller")
	})
	pc.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
		logging.Debugf("[peer] ICE state: %s", state.String())
		if state == webrtc.ICEConnectionStateConnected && p.onICEConnected != nil {
			go p.onICEConnected()
		}
	})
	pc.SCTP().Transport().ICETransport().OnSelectedCandidatePairChange(func(pair *webrtc.ICECandidatePair) {
		p.setSelectedCandidatePair(pc, "controller", pair)
	})
	pc.OnDataChannel(func(dc *webrtc.DataChannel) {
		logging.Debugf("[peer] remote data channel: %s", dc.Label())
		if dc.Label() == LabelBinary {
			p.mu.Lock()
			p.binaryDC = dc
			p.mu.Unlock()
			p.setupBinaryChannel(dc)
		}
	})

	// Create data channels (controller side creates them per DCEP capture)
	binaryDC, err := pc.CreateDataChannel(LabelBinary, &webrtc.DataChannelInit{})
	if err != nil {
		return fmt.Errorf("create binary channel: %w", err)
	}
	p.mu.Lock()
	p.binaryDC = binaryDC
	p.mu.Unlock()
	p.setupBinaryChannel(binaryDC)

	controlDC, err := pc.CreateDataChannel(LabelControl, &webrtc.DataChannelInit{})
	if err != nil {
		return fmt.Errorf("create control channel: %w", err)
	}
	p.mu.Lock()
	p.controlDC = controlDC
	p.mu.Unlock()
	controlDC.OnOpen(func() {
		logging.Debugf("[peer] control channel open")
		p.sendControlHandshake()
	})
	controlDC.OnMessage(func(msg webrtc.DataChannelMessage) {
		p.handleControlEcho(msg.Data)
	})

	textDC, err := pc.CreateDataChannel(LabelText, &webrtc.DataChannelInit{})
	if err != nil {
		return fmt.Errorf("create text channel: %w", err)
	}
	p.mu.Lock()
	p.textDC = textDC
	p.mu.Unlock()
	textDC.OnOpen(func() {
		logging.Debugf("[peer] text channel open")
		p.markTextOpen()
	})
	textDC.OnMessage(func(msg webrtc.DataChannelMessage) {
		p.handleTextMessage(msg.Data)
	})

	// FILE_DATA_CHANNEL carries the pb channel (PortMappingFrame messages)
	fileDC, err := pc.CreateDataChannel(LabelFile, &webrtc.DataChannelInit{})
	if err != nil {
		return fmt.Errorf("create file channel: %w", err)
	}
	p.mu.Lock()
	p.fileDC = fileDC
	p.mu.Unlock()
	fileDC.OnOpen(func() {
		logging.Infof("[peer] file data channel open")
		p.mu.Lock()
		fn := p.onFileOpen
		p.mu.Unlock()
		if fn != nil {
			fn()
		}
	})
	fileDC.OnMessage(func(msg webrtc.DataChannelMessage) {
		if p.onSignalData != nil {
			p.onSignalData(msg.Data)
		}
	})

	offer, err := pc.CreateOffer(nil)
	if err != nil {
		return fmt.Errorf("create offer: %w", err)
	}
	if err := pc.SetLocalDescription(offer); err != nil {
		return fmt.Errorf("set local description: %w", err)
	}

	// Send soac offer with gzip SDP attachment
	gz, err := gzipCompress([]byte(offer.SDP))
	if err != nil {
		return fmt.Errorf("gzip sdp: %w", err)
	}

	payload := map[string]any{
		"client_id": p.routingClientID,
		"data": map[string]any{
			"app_control_id":   p.appControlID,
			"gzip_sdp":         map[string]any{"_placeholder": true, "num": 0},
			"ice_id":           p.iceID,
			"ice_network_type": 3,
			"sdp":              "",
			"type":             "offer",
		},
	}

	if p.sdpOfferFile != "" {
		// File-based SDP exchange: wait for ICE gathering to finish so the
		// serialized local description contains all candidates, then write
		// the offer and poll for the guest's answer file.
		gatherDone := webrtc.GatheringCompletePromise(pc)
		<-gatherDone
		complete := pc.LocalDescription()
		offerData, err := json.Marshal(map[string]string{
			"type": "offer",
			"sdp":  complete.SDP,
		})
		if err != nil {
			return fmt.Errorf("marshal file offer: %w", err)
		}
		if err := os.WriteFile(p.sdpOfferFile, offerData, 0600); err != nil {
			return fmt.Errorf("write offer file: %w", err)
		}
		logging.Debugf("[peer] wrote file offer to %s (sdp %d bytes)", p.sdpOfferFile, len(complete.SDP))

		answerData, err := waitForFile(p.sdpAnswerFile, 90*time.Second)
		if err != nil {
			return fmt.Errorf("wait for answer file: %w", err)
		}
		var answerDesc struct {
			Type string `json:"type"`
			SDP  string `json:"sdp"`
		}
		if err := json.Unmarshal(answerData, &answerDesc); err != nil {
			return fmt.Errorf("parse answer file: %w", err)
		}
		if answerDesc.Type != "answer" || answerDesc.SDP == "" {
			return fmt.Errorf("answer file has type=%q or empty sdp", answerDesc.Type)
		}
		answer := webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: answerDesc.SDP}
		if err := pc.SetRemoteDescription(answer); err != nil {
			return fmt.Errorf("set file answer: %w", err)
		}
		logging.Debugf("[peer] applied file answer from %s (sdp %d bytes)", p.sdpAnswerFile, len(answerDesc.SDP))
		return nil
	}

	logging.Debugf("[peer] sending soac offer (sdp %d bytes, gzip %d)", len(offer.SDP), len(gz))
	return p.sig.EmitBinary("soac", payload, gz)
}

func waitForFile(path string, timeout time.Duration) ([]byte, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil && len(data) > 0 {
			return data, nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return nil, fmt.Errorf("timeout waiting for %s", path)
}

func (p *Peer) onICECandidate(candidate *webrtc.ICECandidate) {
	if candidate == nil {
		return
	}
	cand := candidate.ToJSON()
	sdpMid := ""
	if cand.SDPMid != nil {
		sdpMid = *cand.SDPMid
	}
	mline := uint16(0)
	if cand.SDPMLineIndex != nil {
		mline = *cand.SDPMLineIndex
	}

	payload := map[string]any{
		"client_id": p.routingClientID,
		"data": map[string]any{
			"app_control_id": p.appControlID,
			"candidate": map[string]any{
				"candidate":     cand.Candidate,
				"sdpMLineIndex": mline,
				"sdpMid":        sdpMid,
			},
			"ice_id": p.iceID,
			"type":   "candidate",
		},
	}

	if err := p.sig.Emit("soac", payload); err != nil {
		logging.Errorf("[peer] send candidate error: %v", err)
	}
}

// handleSOAC processes incoming soac events (answer + candidates).
func (p *Peer) handleSOAC(ev *signaling.Event) {
	msg, ok := parseSOACEvent(ev)
	if !ok {
		logging.Errorf("[peer] soac parse error")
		return
	}

	switch msg.Data.Type {
	case "answer":
		sdp := msg.Data.SDP
		if sdp == "" && msg.Data.GzipSDP != "" && !strings.HasPrefix(msg.Data.GzipSDP, "{") {
			// gzip_sdp placeholder was spliced with decompressed content
			sdp = msg.Data.GzipSDP
		}
		if sdp == "" {
			logging.Errorf("[peer] answer with empty sdp")
			return
		}
		answer := webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: sdp}
		if err := p.pc.SetRemoteDescription(answer); err != nil {
			logging.Errorf("[peer] set remote answer error: %v", err)
		} else {
			logging.Debugf("[peer] remote answer set (sdp %d bytes)", len(sdp))
			p.drainPendingCandidates()
		}

	case "candidate":
		p.addRemoteCandidate(webrtc.ICECandidateInit{
			Candidate:     msg.Data.Candidate.Candidate,
			SDPMid:        &msg.Data.Candidate.SDPMid,
			SDPMLineIndex: &msg.Data.Candidate.SDPMLineIndex,
		})

	default:
		logging.Debugf("[peer] soac type=%s ignored", msg.Data.Type)
	}
}

func parseSOACEvent(ev *signaling.Event) (soacEvent, bool) {
	var msg soacEvent
	if len(ev.Args) == 0 {
		return msg, false
	}
	if err := json.Unmarshal(ev.Args[0], &msg); err != nil {
		return msg, false
	}
	return msg, true
}

func (p *Peer) handleControlledSOAC(ev *signaling.Event) {
	p.soacMu.Lock()
	defer p.soacMu.Unlock()

	select {
	case <-p.statsDone:
		return
	default:
	}
	msg, ok := parseSOACEvent(ev)
	if !ok {
		logging.Errorf("[peer] controlled soac parse error")
		return
	}

	switch msg.Data.Type {
	case "offer":
		if p.pc != nil {
			if msg.Data.IceID != "" && msg.Data.IceID != p.iceID {
				p.restartOnce.Do(func() { close(p.restartRequested) })
				logging.Infof("[peer] replacement controller offer; requesting fresh session")
			}
			logging.Debugf("[peer] controlled peer already has an offer; ignoring duplicate")
			return
		}
		if err := p.answerControlledOffer(msg); err != nil {
			// Drop the half-built connection so the controller's next offer is
			// answered instead of being rejected as a duplicate.
			p.resetControlledConnection()
			logging.Errorf("[peer] controlled offer failed: %v", err)
		}

	case "candidate":
		if msg.Data.IceID != "" && msg.Data.IceID != p.iceID {
			return
		}
		if p.pc == nil {
			logging.Debugf("[peer] controlled candidate before offer ignored")
			return
		}
		p.addRemoteCandidate(webrtc.ICECandidateInit{
			Candidate:     msg.Data.Candidate.Candidate,
			SDPMid:        &msg.Data.Candidate.SDPMid,
			SDPMLineIndex: &msg.Data.Candidate.SDPMLineIndex,
		})

	default:
		logging.Debugf("[peer] controlled soac type=%s ignored", msg.Data.Type)
	}
}

// answerControlledOffer builds the controlled-side PeerConnection for one soac
// offer and sends the answer. It must run with soacMu held.
func (p *Peer) answerControlledOffer(msg soacEvent) error {
	offer := webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: msg.Data.SDP}
	if offer.SDP == "" && msg.Data.GzipSDP != "" && !strings.HasPrefix(msg.Data.GzipSDP, "{") {
		offer.SDP = msg.Data.GzipSDP
	}
	if offer.SDP == "" {
		return fmt.Errorf("offer has empty SDP")
	}

	p.appControlID = msg.Data.AppControlID
	p.iceID = msg.Data.IceID
	// soac frames are routed by the controller's client_id. A controlled
	// peer echoes that ID rather than using its own room_info client_id.
	p.routingClientID = msg.ClientID

	pc, err := webrtc.NewPeerConnection(webrtc.Configuration{
		ICEServers: controlledSTUNServers,
	})
	if err != nil {
		return fmt.Errorf("new peer connection: %w", err)
	}
	p.mu.Lock()
	p.pc = pc
	p.mu.Unlock()
	pc.OnICECandidate(p.onICECandidate)
	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		logging.Infof("[peer] connection state: %s", state.String())
		p.logConnectionStats(pc, "controlled")
	})
	pc.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
		logging.Debugf("[peer] ICE state: %s", state.String())
		if state == webrtc.ICEConnectionStateConnected && p.onICEConnected != nil {
			go p.onICEConnected()
		}
	})
	pc.SCTP().Transport().ICETransport().OnSelectedCandidatePairChange(func(pair *webrtc.ICECandidatePair) {
		p.setSelectedCandidatePair(pc, "controlled", pair)
	})
	pc.OnDataChannel(p.setupControlledDataChannel)

	if err := pc.SetRemoteDescription(offer); err != nil {
		return fmt.Errorf("set remote offer: %w", err)
	}
	p.drainPendingCandidates()

	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		return fmt.Errorf("create answer: %w", err)
	}
	if err := pc.SetLocalDescription(answer); err != nil {
		return fmt.Errorf("set local answer: %w", err)
	}

	gz, err := gzipCompress([]byte(answer.SDP))
	if err != nil {
		return fmt.Errorf("gzip answer: %w", err)
	}
	payload := map[string]any{
		"client_id": p.routingClientID,
		"data": map[string]any{
			"app_control_id":   p.appControlID,
			"gzip_sdp":         map[string]any{"_placeholder": true, "num": 0},
			"ice_id":           p.iceID,
			"ice_network_type": 3,
			"sdp":              "",
			"type":             "answer",
		},
	}
	logging.Debugf("[peer] sending controlled soac answer (sdp %d bytes, gzip %d)",
		len(answer.SDP), len(gz))
	if err := p.sig.EmitBinary("soac", payload, gz); err != nil {
		return fmt.Errorf("send answer: %w", err)
	}
	return nil
}

// resetControlledConnection discards a failed controlled PeerConnection so the
// next offer can be answered. It must run with soacMu held.
func (p *Peer) resetControlledConnection() {
	p.mu.Lock()
	pc := p.pc
	p.pc = nil
	p.remoteDescSet = false
	p.pendingCandidates = nil
	p.mu.Unlock()
	if pc != nil {
		_ = pc.Close()
	}
}

func (p *Peer) addRemoteCandidate(cand webrtc.ICECandidateInit) {
	p.mu.Lock()
	p.remoteCandidates = append(p.remoteCandidates, cand.Candidate)
	if !p.remoteDescSet {
		p.pendingCandidates = append(p.pendingCandidates, cand)
		p.mu.Unlock()
		return
	}
	pc := p.pc
	p.mu.Unlock()
	if pc == nil {
		return
	}
	if err := pc.AddICECandidate(cand); err != nil {
		logging.Errorf("[peer] add candidate error: %v", err)
	}
}

func (p *Peer) drainPendingCandidates() {
	p.mu.Lock()
	p.remoteDescSet = true
	pending := append([]webrtc.ICECandidateInit(nil), p.pendingCandidates...)
	p.pendingCandidates = nil
	pc := p.pc
	p.mu.Unlock()
	if pc == nil {
		return
	}
	for _, cand := range pending {
		if err := pc.AddICECandidate(cand); err != nil {
			logging.Errorf("[peer] add pending candidate error: %v", err)
		}
	}
}

func (p *Peer) setupControlledDataChannel(dc *webrtc.DataChannel) {
	logging.Debugf("[peer] controlled remote data channel: %s", dc.Label())
	switch dc.Label() {
	case LabelBinary:
		p.mu.Lock()
		p.binaryDC = dc
		p.mu.Unlock()
		p.setupBinaryChannel(dc)
	case LabelControl:
		p.mu.Lock()
		p.controlDC = dc
		p.mu.Unlock()
		dc.OnOpen(func() { logging.Debugf("[peer] controlled control channel open") })
		dc.OnMessage(func(msg webrtc.DataChannelMessage) { p.handleControlEcho(msg.Data) })
	case LabelText:
		p.mu.Lock()
		p.textDC = dc
		p.mu.Unlock()
		dc.OnOpen(func() {
			logging.Debugf("[peer] controlled text channel open")
			p.markTextOpen()
		})
		dc.OnMessage(func(msg webrtc.DataChannelMessage) { p.handleTextMessage(msg.Data) })
	case LabelFile:
		p.mu.Lock()
		p.fileDC = dc
		p.mu.Unlock()
		dc.OnOpen(func() { logging.Infof("[peer] file data channel open") })
		dc.OnOpen(func() {
			p.mu.Lock()
			fn := p.onFileOpen
			p.mu.Unlock()
			if fn != nil {
				fn()
			}
		})
		dc.OnMessage(func(msg webrtc.DataChannelMessage) {
			if p.onSignalData != nil {
				p.onSignalData(msg.Data)
			}
		})
	}
}

// SendBinary sends data on the BINARY_DATA_CHANNEL.
func (p *Peer) SendBinary(data []byte) error {
	p.mu.Lock()
	dc := p.binaryDC
	p.mu.Unlock()
	if dc == nil {
		return fmt.Errorf("binary data channel not ready")
	}
	return dc.Send(data)
}

// SendControl sends data on the CONTROL_DATA_CHANNEL.
func (p *Peer) SendControl(data []byte) error {
	p.mu.Lock()
	dc := p.controlDC
	p.mu.Unlock()
	if dc == nil {
		return fmt.Errorf("control data channel not ready")
	}
	return dc.Send(data)
}

func (p *Peer) sendControlHandshake() {
	frames := [][]byte{
		mustHex("10c4d8d1d4061a12221008061002180120023002380240024801"),
		mustHex("080110c4d8d1d4061a12221008061002180120023002380240024801"),
		mustHex("080210c4d8d1d4061a12221008061002180120023002380240024801"),
	}
	for _, frame := range frames {
		if err := p.SendControl(frame); err != nil {
			logging.Errorf("[peer] control handshake send error: %v", err)
			return
		}
	}
}

func (p *Peer) sendTextHandshake() {
	frame := mustHex("080410c4d8d1d4066a040a020102")
	if err := p.SendText(frame); err != nil {
		logging.Errorf("[peer] text handshake send error: %v", err)
	}
}

func (p *Peer) handleControlEcho(data []byte) {
	remoteSeq, remoteFeatureFlags, ok := parseControlEcho(data)
	if !ok {
		return
	}
	p.controlEchoOnce.Do(func() {
		args := fmt.Appendf(nil, `{"seq":%d}`, remoteSeq)
		inner := appendPBVarintField(nil, 1, 1)
		inner = appendPBBytesField(inner, 2, args)
		inner = appendPBBytesField(inner, 4, remoteFeatureFlags)

		out := appendPBVarintField(nil, 1, 3)
		out = appendPBVarintField(out, 2, uint64(time.Now().Unix()))
		out = appendPBBytesField(out, 3, inner)

		if err := p.SendControl(out); err != nil {
			logging.Errorf("[peer] control echo send error: %v", err)
			return
		}
		p.sendTextHandshake()
	})
}

func parseControlEcho(data []byte) (uint64, []byte, bool) {
	remoteSeq, ok := pbVarint(data, 1)
	if !ok || remoteSeq == 0 {
		return 0, nil, false
	}

	outerField, ok := pbField(data, 3)
	if !ok {
		return 0, nil, false
	}

	action, ok := pbVarint(outerField, 1)
	if !ok || action != 1 {
		return 0, nil, false
	}
	remoteFeatureFlags, ok := pbBytes(outerField, 4)
	if !ok || len(remoteFeatureFlags) == 0 {
		return 0, nil, false
	}
	return remoteSeq, append([]byte(nil), remoteFeatureFlags...), true
}

func pbField(data []byte, want uint64) ([]byte, bool) {
	pos := 0
	for pos < len(data) {
		tag, n := readPBVarint(data[pos:])
		if n == 0 {
			return nil, false
		}
		pos += n
		fieldNum := tag >> 3
		wireType := tag & 7
		if wireType != 2 {
			if wireType == 0 {
				_, n := readPBVarint(data[pos:])
				if n == 0 {
					return nil, false
				}
				pos += n
				continue
			}
			return nil, false
		}
		length, n := readPBVarint(data[pos:])
		if n == 0 || int(length) > len(data)-pos-n {
			return nil, false
		}
		start := pos + n
		end := start + int(length)
		if fieldNum == want {
			return data[start:end], true
		}
		pos = end
	}
	return nil, false
}

func pbVarint(data []byte, want uint64) (uint64, bool) {
	pos := 0
	for pos < len(data) {
		tag, n := readPBVarint(data[pos:])
		if n == 0 {
			return 0, false
		}
		pos += n
		fieldNum := tag >> 3
		wireType := tag & 7
		if wireType == 0 {
			value, n := readPBVarint(data[pos:])
			if n == 0 {
				return 0, false
			}
			pos += n
			if fieldNum == want {
				return value, true
			}
			continue
		}
		if wireType != 2 {
			return 0, false
		}
		length, n := readPBVarint(data[pos:])
		if n == 0 || int(length) > len(data)-pos-n {
			return 0, false
		}
		pos += n + int(length)
	}
	return 0, false
}

func pbBytes(data []byte, want uint64) ([]byte, bool) {
	return pbField(data, want)
}

func appendPBVarintField(buf []byte, fieldNum, value uint64) []byte {
	buf = appendPBVarint(buf, fieldNum<<3)
	return appendPBVarint(buf, value)
}

func appendPBBytesField(buf []byte, fieldNum uint64, value []byte) []byte {
	buf = appendPBVarint(buf, (fieldNum<<3)|2)
	buf = appendPBVarint(buf, uint64(len(value)))
	return append(buf, value...)
}

func appendPBVarint(buf []byte, v uint64) []byte {
	for v >= 0x80 {
		buf = append(buf, byte(v)|0x80)
		v >>= 7
	}
	return append(buf, byte(v))
}

func readPBVarint(data []byte) (uint64, int) {
	var v uint64
	for i := 0; i < len(data) && i < 10; i++ {
		b := data[i]
		v |= uint64(b&0x7f) << (7 * i)
		if b < 0x80 {
			return v, i + 1
		}
	}
	return 0, 0
}

func (p *Peer) markTextOpen() {
	p.textOpenOnce.Do(func() { close(p.textOpen) })
}

// TextChannelOpen reports when TEXT_DATA_CHANNEL is usable. The mode callback
// fires while ICE is still selecting a candidate pair, well before the data
// channels exist, so anything that sends on this channel has to wait for it.
func (p *Peer) TextChannelOpen() <-chan struct{} {
	return p.textOpen
}

// maxPendingText bounds the messages held for a handler that is not installed
// yet. The channel carries short control messages only.
const maxPendingText = 16

// OnTextMessage registers a handler for TEXT_DATA_CHANNEL payloads. uulink
// uses this channel for its own peer-to-peer control messages; the official
// client only sends a fixed protobuf handshake on it, which the handler is
// expected to ignore.
//
// Messages that arrived before this call are replayed, because the peer is
// wired up while the channel is already open and the remote side may have
// spoken first.
func (p *Peer) OnTextMessage(fn func([]byte)) {
	p.mu.Lock()
	p.onTextMessage = fn
	pending := p.pendingText
	p.pendingText = nil
	p.mu.Unlock()
	if fn == nil {
		return
	}
	for _, data := range pending {
		fn(data)
	}
}

func (p *Peer) handleTextMessage(data []byte) {
	p.mu.Lock()
	fn := p.onTextMessage
	if fn == nil {
		if len(p.pendingText) < maxPendingText {
			p.pendingText = append(p.pendingText, append([]byte(nil), data...))
		}
		p.mu.Unlock()
		return
	}
	p.mu.Unlock()
	fn(data)
}

func (p *Peer) SendText(data []byte) error {
	p.mu.Lock()
	dc := p.textDC
	p.mu.Unlock()
	if dc == nil {
		return fmt.Errorf("text data channel not ready")
	}
	return dc.Send(data)
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// SendSignalPB sends a binary gvpb Message on FILE_DATA_CHANNEL. The official
// client logs this path as sentProtocolBufferfile/streamerDidReceiveFileData.
func (p *Peer) SendSignalPB(msg []byte) error {
	p.mu.Lock()
	dc := p.fileDC
	p.mu.Unlock()
	if dc == nil {
		return fmt.Errorf("file data channel not ready")
	}
	return dc.SendText(string(msg))
}

// OnBinaryChannelOpen registers a callback fired when the binary channel opens.
func (p *Peer) OnBinaryChannelOpen(fn func()) {
	p.mu.Lock()
	p.onBinaryOpen = fn
	dc := p.binaryDC
	p.mu.Unlock()
	if dc != nil && dc.ReadyState() == webrtc.DataChannelStateOpen {
		fn()
	}
}

// OnFileChannelOpen registers a callback fired when FILE_DATA_CHANNEL opens.
// If the channel is already open, the callback runs immediately.
func (p *Peer) OnFileChannelOpen(fn func()) {
	p.mu.Lock()
	p.onFileOpen = fn
	dc := p.fileDC
	p.mu.Unlock()
	if dc != nil && dc.ReadyState() == webrtc.DataChannelStateOpen {
		fn()
	}
}

// OnICEConnected registers a callback fired once when ICE reaches the
// connected state. Used to start the mix-kcp send path at the right moment.
func (p *Peer) OnICEConnected(fn func()) {
	p.mu.Lock()
	p.onICEConnected = fn
	p.mu.Unlock()
}

// TransportMode returns the effective mode resolved before peer creation.
func (p *Peer) TransportMode() TransportMode {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.effectiveTransportMode == "" {
		return TransportAuto
	}
	return p.effectiveTransportMode
}

// SelectedPairMode reports the candidate type of the selected ICE pair.
func (p *Peer) SelectedPairMode() string {
	p.mu.Lock()
	pair := p.selectedPair
	p.mu.Unlock()
	if pair == nil {
		return "unavailable"
	}
	return candidatePairMode(pair)
}

// ValidateTransportMode refuses to start the data plane when relay was
// required but the selected ICE pair is not relayed.
func (p *Peer) ValidateTransportMode() error {
	if p.TransportMode() != TransportRelay {
		return nil
	}
	mode := p.SelectedPairMode()
	if mode != "relay" {
		return fmt.Errorf("transport relay required but selected candidate pair mode=%s", mode)
	}
	return nil
}

// RemoteCandidates returns the remote ICE candidate strings received via soac
// candidate events (host candidates first — they carry the LAN address the
// official client sends mix-kcp frames to).
func (p *Peer) RemoteCandidates() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, len(p.remoteCandidates))
	copy(out, p.remoteCandidates)
	return out
}

// BinaryChannelOpen returns whether the binary channel is open.
func (p *Peer) BinaryChannelOpen() bool {
	p.mu.Lock()
	dc := p.binaryDC
	p.mu.Unlock()
	return dc != nil && dc.ReadyState() == webrtc.DataChannelStateOpen
}

// OnModeChange registers a callback invoked with "direct" or "relay" whenever
// a selected ICE candidate pair is established.
func (p *Peer) OnModeChange(fn func(string)) {
	p.mu.Lock()
	p.onModeChange = fn
	p.mu.Unlock()
}

func candidatePairMode(pair *webrtc.ICECandidatePair) string {
	if pair != nil && pair.Local != nil && pair.Remote != nil &&
		(pair.Local.Typ == webrtc.ICECandidateTypeRelay || pair.Remote.Typ == webrtc.ICECandidateTypeRelay) {
		return "relay"
	}
	return "direct"
}

func (p *Peer) setSelectedCandidatePair(pc *webrtc.PeerConnection, role string, pair *webrtc.ICECandidatePair) {
	if pair == nil || pair.Local == nil || pair.Remote == nil {
		logging.Warnf("[peer] selected candidate pair unavailable")
		return
	}

	p.mu.Lock()
	p.selectedPair = pair
	running := p.statsRunning
	p.statsRunning = true
	callback := p.onModeChange
	p.mu.Unlock()
	if !running {
		go p.statsLoop(pc, role)
	}
	p.logConnectionStats(pc, role)
	if callback != nil {
		callback(candidatePairMode(pair))
	}
}

func (p *Peer) statsLoop(pc *webrtc.PeerConnection, role string) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-p.statsDone:
			return
		case <-ticker.C:
			p.logConnectionStats(pc, role)
		}
	}
}

func (p *Peer) logConnectionStats(pc *webrtc.PeerConnection, role string) {
	p.mu.Lock()
	pair := p.selectedPair
	p.mu.Unlock()
	if pair == nil || pair.Local == nil || pair.Remote == nil {
		return
	}

	rtt := "unavailable"
	var bytesSent, bytesReceived uint64
	if stats, ok := pc.GetStats().GetICECandidatePairStats(pair); ok {
		if stats.CurrentRoundTripTime > 0 {
			rtt = strconv.FormatFloat(stats.CurrentRoundTripTime*1000, 'f', 1, 64) + "ms"
		}
		bytesSent = stats.BytesSent
		bytesReceived = stats.BytesReceived
	}

	logging.Infof(
		"[%s peer] connection status: state=%s mode=%s local=%s:%d/%s remote=%s:%d/%s rtt=%s sent=%dB received=%dB",
		role, pc.ConnectionState().String(), candidatePairMode(pair),
		pair.Local.Address, pair.Local.Port, pair.Local.Typ,
		pair.Remote.Address, pair.Remote.Port, pair.Remote.Typ,
		rtt, bytesSent, bytesReceived,
	)
}

// Close shuts down the peer connection.
func (p *Peer) Close() error {
	p.mu.Lock()
	select {
	case <-p.statsDone:
	default:
		close(p.statsDone)
	}
	p.mu.Unlock()

	p.mu.Lock()
	pc := p.pc
	p.mu.Unlock()
	if pc != nil {
		return pc.Close()
	}
	return nil
}

func (p *Peer) setupBinaryChannel(dc *webrtc.DataChannel) {
	dc.OnOpen(func() {
		logging.Debugf("[peer] binary data channel open")
		p.mu.Lock()
		fn := p.onBinaryOpen
		p.mu.Unlock()
		if fn != nil {
			fn()
		}
	})
	dc.OnClose(func() {
		logging.Debugf("[peer] binary data channel closed")
	})
	dc.OnMessage(func(msg webrtc.DataChannelMessage) {
		if p.onBinaryData != nil {
			p.onBinaryData(msg.Data)
		}
	})
}

func gzipCompress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func randomUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// RestartRequested closes when this room receives a new controller incarnation.
func (p *Peer) RestartRequested() <-chan struct{} { return p.restartRequested }

// ConnectionState returns a synchronized snapshot for transport watchdogs.
func (p *Peer) ConnectionState() string {
	p.mu.Lock()
	pc := p.pc
	p.mu.Unlock()
	if pc == nil {
		return "new"
	}
	return pc.ConnectionState().String()
}
