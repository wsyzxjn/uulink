//go:build integration

package peer

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
	"github.com/wsyzxjn/uulink/pkg/logging"
	"github.com/wsyzxjn/uulink/pkg/settings"
	"github.com/wsyzxjn/uulink/pkg/tunnel"
)

// BenchmarkLoopbackTunnel measures verified TCP echo traffic through the real
// tunnel, Peer.SendSignalPB and Pion stack. It excludes connection setup and
// uses direct local ICE candidates; it does not measure a WAN or TURN relay.
func BenchmarkLoopbackTunnel(b *testing.B) {
	level := logging.CurrentLevel()
	logging.SetLevel(logging.LevelWarn)
	b.Cleanup(func() { logging.SetLevel(level) })
	for _, streams := range []int{1, 4} {
		b.Run(fmt.Sprintf("streams=%d", streams), func(b *testing.B) {
			b.StopTimer()
			addr := loopbackTunnel(b)
			conns := make([]net.Conn, streams)
			payload := make([]byte, 256<<10)
			for i := range payload {
				payload[i] = byte(i * 31)
			}
			for i := range conns {
				conn, err := net.DialTimeout("tcp", addr, time.Second)
				if err != nil {
					b.Fatal(err)
				}
				b.Cleanup(func() { _ = conn.Close() })
				_ = conn.SetDeadline(time.Now().Add(5 * time.Minute))
				conns[i] = conn
				if _, err := conn.Write([]byte("warmup")); err != nil {
					b.Fatal(err)
				}
				warmup := make([]byte, 6)
				if _, err := io.ReadFull(conn, warmup); err != nil || string(warmup) != "warmup" {
					b.Fatalf("warmup = %q, err=%v", warmup, err)
				}
			}
			b.SetBytes(int64(streams * len(payload)))
			b.ReportAllocs()
			errors := make(chan error, streams)
			var wg sync.WaitGroup
			b.ResetTimer()
			b.StartTimer()
			for _, conn := range conns {
				wg.Add(1)
				go func() {
					defer wg.Done()
					received := make([]byte, len(payload))
					for range b.N {
						if _, err := conn.Write(payload); err != nil {
							errors <- err
							return
						}
						if _, err := io.ReadFull(conn, received); err != nil {
							errors <- err
							return
						}
						if !bytes.Equal(received, payload) {
							errors <- fmt.Errorf("echo payload mismatch")
							return
						}
					}
				}()
			}
			wg.Wait()
			b.StopTimer()
			close(errors)
			for err := range errors {
				b.Fatal(err)
			}
		})
	}
}

func loopbackTunnel(t testing.TB) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	network := settings.Defaults()
	makePeer := func() *Peer {
		pc, err := newWebRTCAPI(network).NewPeerConnection(webrtc.Configuration{})
		if err != nil {
			t.Fatal(err)
		}
		p := &Peer{pc: pc, network: network, statsDone: make(chan struct{})}
		t.Cleanup(func() { _ = p.Close() })
		return p
	}
	a, z := makePeer(), makePeer()
	tunA := tunnel.NewTunnelWithRules([]tunnel.Rule{{ID: "1", LocalHost: "127.0.0.1", TargetHost: "127.0.0.1", TargetPort: ln.Addr().(*net.TCPAddr).Port}}, peerFrameSender{a})
	tunZ := tunnel.NewTunnelWithRules(nil, peerFrameSender{z})
	t.Cleanup(tunA.Stop)
	t.Cleanup(tunZ.Stop)
	a.onSignalData, z.onSignalData = tunA.HandleMessage, tunZ.HandleMessage
	ready := make(chan struct{})
	a.onFileOpen = func() { close(ready) }
	z.pc.OnDataChannel(z.setupControlledDataChannel)
	dc, err := a.pc.CreateDataChannel(LabelFile, nil)
	if err != nil {
		t.Fatal(err)
	}
	a.setupControlledDataChannel(dc)
	negotiate := func(from, to *webrtc.PeerConnection, description webrtc.SessionDescription) {
		gathered := webrtc.GatheringCompletePromise(from)
		if err := from.SetLocalDescription(description); err != nil {
			t.Fatal(err)
		}
		select {
		case <-gathered:
		case <-time.After(10 * time.Second):
			t.Fatal("ICE gathering timeout")
		}
		if err := to.SetRemoteDescription(*from.LocalDescription()); err != nil {
			t.Fatal(err)
		}
	}
	offer, err := a.pc.CreateOffer(nil)
	if err != nil {
		t.Fatal(err)
	}
	negotiate(a.pc, z.pc, offer)
	answer, err := z.pc.CreateAnswer(nil)
	if err != nil {
		t.Fatal(err)
	}
	negotiate(z.pc, a.pc, answer)
	select {
	case <-ready:
	case <-time.After(10 * time.Second):
		t.Fatal("file channel readiness timeout")
	}
	if err := tunA.Start(); err != nil {
		t.Fatal(err)
	}
	addr, err := tunA.ListenerAddr("1")
	if err != nil {
		t.Fatal(err)
	}
	return addr.String()
}
