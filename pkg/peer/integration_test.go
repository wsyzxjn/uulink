package peer

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/wsyzxjn/uulink/pkg/signaling"
	"github.com/wsyzxjn/uulink/pkg/tunnel"
)

type fakeSignalingServer struct {
	server           *httptest.Server
	mu               sync.Mutex
	writeMu          sync.Mutex
	conns            map[string]*websocket.Conn
	pending          map[string]string
	controlledSOAC   []string
	controllerEvents []string
}

func newFakeSignalingServer() *fakeSignalingServer {
	s := &fakeSignalingServer{
		conns:   make(map[string]*websocket.Conn),
		pending: make(map[string]string),
	}
	s.server = httptest.NewServer(s)
	return s
}

func (s *fakeSignalingServer) URL() string {
	return strings.Replace(s.server.URL, "http://", "ws://", 1) + "/"
}

func (s *fakeSignalingServer) Close() {
	s.mu.Lock()
	conns := make([]*websocket.Conn, 0, len(s.conns))
	for _, conn := range s.conns {
		conns = append(conns, conn)
	}
	s.mu.Unlock()
	for _, conn := range conns {
		conn.Close()
	}
	s.server.Close()
}

func (s *fakeSignalingServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	role := "controlled"
	if r.Header.Get("X-NRD-CONTROLLING") == "1" {
		role = "controller"
	}

	conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	s.mu.Lock()
	s.conns[role] = conn
	s.mu.Unlock()

	s.write(conn, `0{"sid":"fake","pingInterval":1000000,"pingTimeout":1000000}`)
	for {
		messageType, msg, err := conn.ReadMessage()
		if err != nil {
			return
		}
		if messageType == websocket.TextMessage {
			if err := s.handleText(role, conn, string(msg)); err != nil {
				return
			}
			continue
		}
		s.handleBinary(role, msg)
	}
}

func (s *fakeSignalingServer) handleText(role string, conn *websocket.Conn, text string) error {
	switch {
	case text == "40":
		s.write(conn, `40{"sid":"fake-connected"}`)
	case text == "2":
		s.write(conn, "3")
	case strings.HasPrefix(text, "42"):
		if strings.Contains(text, `"room_info"`) {
			rest := text[2:]
			before, _, ok := strings.Cut(rest, "[")
			if !ok {
				return nil
			}
			ackID := before
			s.write(conn, `43`+ackID+`[{"room_id":"fake-room","you":{"client_id":"controlled-client","device_id":"controlled-device"}}]`)
			return nil
		}
		if strings.Contains(text, `"refresh_reconnect_key"`) {
			rest := text[2:]
			before, _, ok := strings.Cut(rest, "[")
			if !ok {
				return nil
			}
			ackID := before
			if role == "controller" {
				s.recordControllerEvent("refresh_reconnect_key")
			}
			s.write(conn, `43`+ackID+`["success",{"reconnect_key":"fake-reconnect-key"}]`)
			return nil
		}
		if strings.Contains(text, `"soac"`) {
			if role == "controlled" {
				s.mu.Lock()
				s.controlledSOAC = append(s.controlledSOAC, text)
				s.mu.Unlock()
			}
			s.routeText(otherRole(role), text)
		}
	case strings.HasPrefix(text, "45"):
		s.mu.Lock()
		s.pending[role] = text
		s.mu.Unlock()
	}
	return nil
}

func (s *fakeSignalingServer) handleBinary(role string, attachment []byte) {
	s.mu.Lock()
	text := s.pending[role]
	delete(s.pending, role)
	s.mu.Unlock()
	if text == "" {
		return
	}

	if strings.Contains(text, `"control"`) && role == "controller" {
		s.recordControllerEvent("control")
		rest := text[3:]
		dash := strings.IndexByte(rest, '-')
		if dash < 0 {
			return
		}
		rest = rest[dash+1:]
		before, _, ok := strings.Cut(rest, "[")
		if !ok {
			return
		}
		ackID := before
		conn := s.connection(role)
		if conn != nil {
			s.write(conn, `43`+ackID+`["success",{"code":0,"client_id":"controller-client","ice_id":"fake-ice","force_relay":false,"iceServers":[]}]`)
		}
		return
	}

	if strings.Contains(text, `"soac"`) {
		if role == "controlled" {
			s.mu.Lock()
			s.controlledSOAC = append(s.controlledSOAC, text)
			s.mu.Unlock()
		}
		other := s.connection(otherRole(role))
		if other == nil {
			return
		}
		s.write(other, text)
		s.writeMessage(other, websocket.BinaryMessage, attachment)
	}
}

func (s *fakeSignalingServer) recordControllerEvent(event string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.controllerEvents = append(s.controllerEvents, event)
}

func (s *fakeSignalingServer) ControllerEvents() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.controllerEvents...)
}

func (s *fakeSignalingServer) ControlledSOACFrames() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.controlledSOAC...)
}

func (s *fakeSignalingServer) connection(role string) *websocket.Conn {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conns[role]
}

func (s *fakeSignalingServer) routeText(role, text string) {
	conn := s.connection(role)
	if conn != nil {
		s.write(conn, text)
	}
}

func (s *fakeSignalingServer) write(conn *websocket.Conn, text string) {
	s.writeMessage(conn, websocket.TextMessage, []byte(text))
}

func (s *fakeSignalingServer) writeMessage(conn *websocket.Conn, messageType int, data []byte) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_ = conn.WriteMessage(messageType, data)
}

func otherRole(role string) string {
	if role == "controller" {
		return "controlled"
	}
	return "controller"
}

type peerFrameSender struct {
	peer *Peer
}

func (s peerFrameSender) SendFrame(msg []byte) error {
	return s.peer.SendSignalPB(msg)
}

func TestControllerAndControlledPeersCarrySymmetricTunnel(t *testing.T) {
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

	fake := newFakeSignalingServer()
	defer fake.Close()

	controllerSignal, err := signaling.Connect(&signaling.ConnectConfig{
		GatewayURL:  fake.URL(),
		NRDAuth:     "test",
		Controlling: true,
	})
	if err != nil {
		t.Fatalf("connect controller signaling: %v", err)
	}
	defer controllerSignal.Close()

	controlledSignal, err := signaling.Connect(&signaling.ConnectConfig{
		GatewayURL:  fake.URL(),
		NRDAuth:     "test",
		Controlling: false,
	})
	if err != nil {
		t.Fatalf("connect controlled signaling: %v", err)
	}
	defer controlledSignal.Close()

	var controllerTunnel, controlledTunnel *tunnel.Tunnel
	controller, err := NewController(&Config{
		Signal:   controllerSignal,
		DeviceID: "controller-device",
		OnSignalData: func(data []byte) {
			if controllerTunnel != nil {
				controllerTunnel.HandleMessage(data)
			}
		},
	})
	if err != nil {
		t.Fatalf("new controller: %v", err)
	}
	defer controller.Close()

	controlled, err := NewControlled(&Config{
		Signal: controlledSignal,
		OnSignalData: func(data []byte) {
			if controlledTunnel != nil {
				controlledTunnel.HandleMessage(data)
			}
		},
	})
	if err != nil {
		t.Fatalf("new controlled: %v", err)
	}
	defer controlled.Close()

	controllerFileOpen := make(chan struct{})
	controlledFileOpen := make(chan struct{})
	controller.OnFileChannelOpen(func() { close(controllerFileOpen) })
	controlled.OnFileChannelOpen(func() { close(controlledFileOpen) })

	if err := controller.Connect(nil); err != nil {
		t.Fatalf("controller connect: %v", err)
	}
	select {
	case <-controllerFileOpen:
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for controller file channel")
	}
	select {
	case <-controlledFileOpen:
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for controlled file channel")
	}

	controllerTunnel = tunnel.NewTunnel(tunnel.Rule{
		ID:         "3001",
		LocalHost:  "127.0.0.1",
		LocalPort:  0,
		TargetHost: "127.0.0.1",
		TargetPort: targetLn.Addr().(*net.TCPAddr).Port,
	}, peerFrameSender{peer: controller})
	controlledTunnel = tunnel.NewTunnel(tunnel.Rule{
		ID:         "3002",
		LocalHost:  "127.0.0.1",
		LocalPort:  0,
		TargetHost: "127.0.0.1",
		TargetPort: targetLn.Addr().(*net.TCPAddr).Port,
	}, peerFrameSender{peer: controlled})
	defer controllerTunnel.Stop()
	defer controlledTunnel.Stop()

	if err := controllerTunnel.Start(); err != nil {
		t.Fatalf("start controller tunnel: %v", err)
	}
	if err := controlledTunnel.Start(); err != nil {
		t.Fatalf("start controlled tunnel: %v", err)
	}
	listenerAddr, err := controllerTunnel.ListenerAddr("3001")
	if err != nil {
		t.Fatalf("controller listener addr: %v", err)
	}
	reverseListenerAddr, err := controlledTunnel.ListenerAddr("3002")
	if err != nil {
		t.Fatalf("controlled listener addr: %v", err)
	}

	echoes := make(chan string, 2)
	go echoThroughTunnel(t, listenerAddr.String(), "controller-to-controlled", echoes)
	go echoThroughTunnel(t, reverseListenerAddr.String(), "controlled-to-controller", echoes)

	for range 2 {
		select {
		case echo := <-echoes:
			switch echo {
			case "controller-to-controlled", "controlled-to-controller":
			default:
				t.Fatalf("unexpected echo %q", echo)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("timeout waiting for bidirectional tunnel echoes")
		}
	}

	routedToController := false
	routedCandidateToController := false
	for _, frame := range fake.ControlledSOACFrames() {
		if strings.Contains(frame, `"client_id":"controller-client"`) &&
			strings.Contains(frame, `"type":"answer"`) {
			routedToController = true
		}
		if strings.Contains(frame, `"client_id":"controller-client"`) &&
			strings.Contains(frame, `"type":"candidate"`) {
			routedCandidateToController = true
		}
	}
	if !routedToController {
		t.Fatal("controlled answer was not routed with controller client_id")
	}
	if !routedCandidateToController {
		t.Fatal("controlled candidate was not routed with controller client_id")
	}
	events := fake.ControllerEvents()
	wantEvents := []string{"refresh_reconnect_key", "control"}
	if len(events) != len(wantEvents) {
		t.Fatalf("controller event order = %v, want %v", events, wantEvents)
	}
	for i, event := range wantEvents {
		if events[i] != event {
			t.Fatalf("controller event order = %v, want %v", events, wantEvents)
		}
	}
}

func echoThroughTunnel(t *testing.T, address, payload string, result chan<- string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		select {
		case result <- "dial error: " + err.Error():
		default:
		}
		return
	}
	defer conn.Close()

	if _, err := conn.Write([]byte(payload)); err != nil {
		select {
		case result <- "write error: " + err.Error():
		default:
		}
		return
	}
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		select {
		case result <- "read error: " + err.Error():
		default:
		}
		return
	}
	result <- string(buf)
}
