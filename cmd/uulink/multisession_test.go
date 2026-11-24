package main

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/wsyzxjn/uulink/pkg/proto/gvpb"
	"github.com/wsyzxjn/uulink/pkg/tunnel"
)

type frameSenderFunc func([]byte) error

func (f frameSenderFunc) SendFrame(data []byte) error { return f(data) }

func TestSessionReceiverRepliesOnIncomingSession(t *testing.T) {
	pool := tunnel.NewSessionPool(tunnel.PolicyStreamRoundRobin)
	defer pool.Close()
	tun := tunnel.NewTunnelWithRules(nil, pool)
	defer tun.Stop()
	tun.SetSecurityPolicy(tunnel.SecurityPolicy{AllowedPorts: map[int]bool{}})

	frames := make(chan []byte, 1)
	incoming := tunnel.NewSimpleSession("incoming", frameSenderFunc(func(data []byte) error {
		frames <- data
		return nil
	}), nil)
	pool.AddSession(tunnel.NewSimpleSession("other", frameSenderFunc(func([]byte) error {
		t.Error("reply routed to an unrelated session")
		return nil
	}), nil))
	pool.AddSession(incoming)
	wire, err := (&gvpb.Message{PortMappingFrame: &gvpb.PortMappingFrame{
		RuleID: "42", StreamID: "1", Type: gvpb.TypeConnect, Payload: gvpb.NewConnect("127.0.0.1", 22),
	}}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	handleSessionData(tun, pool, incoming, wire)
	select {
	case data := <-frames:
		frame := tunnel.DecodeFrameForTunnel(data)
		if frame == nil || frame.Type != gvpb.TypeSynAck {
			t.Fatalf("expected CONNECT rejection, got %v", frame)
		}
		var ack struct{ OK bool }
		if err := json.Unmarshal(frame.Payload, &ack); err != nil || ack.OK {
			t.Fatalf("invalid rejection: %s, err=%v", frame.Payload, err)
		}
	default:
		t.Fatal("peer-initiated CONNECT received no reply")
	}
}

func TestSessionRepairKeepsHealthySession(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	set := newSessionSet(ctx)
	defer set.closeAll()
	healthy := &sessionRuntime{id: "healthy", done: make(chan struct{})}
	failed := &sessionRuntime{id: "failed", done: make(chan struct{})}
	set.add(healthy)
	set.add(failed)
	set.remove(failed.id)
	repaired := make(chan *sessionRuntime, 1)
	set.maintainSession(failed, func(context.Context) (*sessionRuntime, error) {
		rt := &sessionRuntime{id: "replacement", done: make(chan struct{})}
		repaired <- rt
		return rt, nil
	})
	select {
	case <-repaired:
	case <-time.After(time.Second):
		t.Fatal("failed session was not replaced")
	}
	select {
	case <-healthy.done:
		t.Fatal("repair closed a healthy session")
	case err := <-set.failed:
		t.Fatalf("repair failed the whole pool: %v", err)
	default:
	}
	cancel()
	set.closeAll()
	select {
	case <-healthy.done:
	default:
		t.Fatal("shutdown did not close the healthy session")
	}
}
