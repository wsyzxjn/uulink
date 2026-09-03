package tunnel

import (
	"encoding/json"
	"testing"

	"github.com/user/uulink/pkg/proto/gvpb"
)

func TestIsLoopbackHost(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"127.0.0.1", true},
		{"127.0.0.2", true},
		{"127.10.20.30", true},
		{"::1", true},
		{"[::1]", true},
		{"localhost", true},
		{"localhost.", true},
		{"LOCALHOST", true},
		{"192.168.1.1", false},
		{"10.0.0.1", false},
		{"172.16.0.1", false},
		{"8.8.8.8", false},
		{"0.0.0.0", false},
		{"::", false},
		{"example.com", false},
		{"", false},
	}

	for _, tt := range tests {
		got := isLoopbackHost(tt.host)
		if got != tt.want {
			t.Errorf("isLoopbackHost(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}

func TestParseAllowedPorts(t *testing.T) {
	tests := []struct {
		input   string
		want    []int
		wantErr bool
	}{
		{"", nil, false},
		{"   ", nil, false},
		{"8080", []int{8080}, false},
		{"22, 80, 443", []int{22, 80, 443}, false},
		{"8000-8003, 9000", []int{8000, 8001, 8002, 8003, 9000}, false},
		{"invalid", nil, true},
		{"8080-8070", nil, true},
		{"0", nil, true},
		{"70000", nil, true},
		{"-1", nil, true},
	}

	for _, tt := range tests {
		got, err := ParseAllowedPorts(tt.input)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseAllowedPorts(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			continue
		}
		if !tt.wantErr {
			if len(tt.want) == 0 && len(got) != 0 {
				t.Errorf("ParseAllowedPorts(%q) = %v, want empty", tt.input, got)
			}
			for _, p := range tt.want {
				if !got[p] {
					t.Errorf("ParseAllowedPorts(%q) missing expected port %d", tt.input, p)
				}
			}
		}
	}
}

func TestSecurityPolicyValidateTarget(t *testing.T) {
	// Default policy: loopback only, any port
	defaultPolicy := SecurityPolicy{AllowLAN: false}
	if err := defaultPolicy.ValidateTarget("127.0.0.1", 8080); err != nil {
		t.Errorf("defaultPolicy.ValidateTarget(127.0.0.1:8080) unexpected error: %v", err)
	}
	if err := defaultPolicy.ValidateTarget("localhost", 3389); err != nil {
		t.Errorf("defaultPolicy.ValidateTarget(localhost:3389) unexpected error: %v", err)
	}
	if err := defaultPolicy.ValidateTarget("192.168.1.1", 80); err == nil {
		t.Errorf("defaultPolicy.ValidateTarget(192.168.1.1:80) expected error for non-loopback host")
	}
	if err := defaultPolicy.ValidateTarget("127.0.0.1", 0); err == nil {
		t.Errorf("defaultPolicy.ValidateTarget with port 0 expected error")
	}
	if err := defaultPolicy.ValidateTarget("127.0.0.1", 70000); err == nil {
		t.Errorf("defaultPolicy.ValidateTarget with port 70000 expected error")
	}

	// AllowLAN enabled
	lanPolicy := SecurityPolicy{AllowLAN: true}
	if err := lanPolicy.ValidateTarget("192.168.1.1", 80); err != nil {
		t.Errorf("lanPolicy.ValidateTarget(192.168.1.1:80) unexpected error: %v", err)
	}

	// Port whitelist enabled
	portPolicy := SecurityPolicy{
		AllowLAN:     false,
		AllowedPorts: map[int]bool{8080: true, 22: true},
	}
	if err := portPolicy.ValidateTarget("127.0.0.1", 8080); err != nil {
		t.Errorf("portPolicy.ValidateTarget(127.0.0.1:8080) unexpected error: %v", err)
	}
	if err := portPolicy.ValidateTarget("127.0.0.1", 22); err != nil {
		t.Errorf("portPolicy.ValidateTarget(127.0.0.1:22) unexpected error: %v", err)
	}
	if err := portPolicy.ValidateTarget("127.0.0.1", 3389); err == nil {
		t.Errorf("portPolicy.ValidateTarget(127.0.0.1:3389) expected error for port not in whitelist")
	}
}

func TestHandleConnectSecurityRejection(t *testing.T) {
	sender := newChannelSender()
	defer sender.Close()

	tun := NewTunnelWithRules(nil, sender)
	tun.SetSecurityPolicy(SecurityPolicy{
		AllowLAN:     false,
		AllowedPorts: map[int]bool{8080: true},
	})

	// 1. Send CONNECT with non-loopback host
	blockedHostMsg, err := newConnectMsg("1001", "1", "192.168.1.100", 8080)
	if err != nil {
		t.Fatalf("build connect msg: %v", err)
	}
	tun.HandleMessage(blockedHostMsg)

	respMsg := receiveFrame(t, sender.ch)
	respFrame := decodeFrameForTunnel(respMsg)
	if respFrame == nil {
		t.Fatalf("expected response frame, got nil")
	}
	if respFrame.Type != gvpb.TypeSynAck {
		t.Fatalf("expected SYN_ACK, got %s", respFrame.Type)
	}
	var ack struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal(respFrame.Payload, &ack); err != nil {
		t.Fatalf("unmarshal syn ack payload: %v", err)
	}
	if ack.OK {
		t.Errorf("expected syn ack ok=false for blocked host, got true")
	}

	// 2. Send CONNECT with disallowed port
	blockedPortMsg, err := newConnectMsg("1002", "2", "127.0.0.1", 9999)
	if err != nil {
		t.Fatalf("build connect msg: %v", err)
	}
	tun.HandleMessage(blockedPortMsg)

	respMsg2 := receiveFrame(t, sender.ch)
	respFrame2 := decodeFrameForTunnel(respMsg2)
	if respFrame2 == nil || respFrame2.Type != gvpb.TypeSynAck {
		t.Fatalf("expected SYN_ACK response, got %v", respFrame2)
	}
	var ack2 struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal(respFrame2.Payload, &ack2); err != nil {
		t.Fatalf("unmarshal syn ack payload: %v", err)
	}
	if ack2.OK {
		t.Errorf("expected syn ack ok=false for blocked port, got true")
	}
}
