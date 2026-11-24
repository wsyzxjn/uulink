//go:build integration

package main

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/wsyzxjn/uulink/pkg/tunnel"
)

func TestPooledSessionsCarryBidirectionalTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
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
	var pools [2]*tunnel.SessionPool
	var tunnels [2]*tunnel.Tunnel
	for side := range pools {
		pools[side] = tunnel.NewSessionPool(tunnel.PolicyStreamRoundRobin)
		defer pools[side].Close()
		tunnels[side] = tunnel.NewTunnelWithRules([]tunnel.Rule{{ID: fmt.Sprint(side + 1), LocalHost: "127.0.0.1", TargetHost: "127.0.0.1", TargetPort: ln.Addr().(*net.TCPAddr).Port}}, pools[side])
		defer tunnels[side].Stop()
	}
	done := make(chan struct{})
	defer close(done)
	for index := range 2 {
		var sessions [2]*tunnel.SimpleSession
		queues := [2]chan []byte{make(chan []byte, 64), make(chan []byte, 64)}
		for side := range pools {
			sessions[side] = tunnel.NewSimpleSession(fmt.Sprint(index), frameSenderFunc(func(data []byte) error {
				select {
				case queues[1-side] <- data:
					return nil
				case <-done:
					return net.ErrClosed
				}
			}), nil)
			pools[side].AddSession(sessions[side])
		}
		for side := range pools {
			go func() {
				for {
					select {
					case data := <-queues[side]:
						handleSessionData(tunnels[side], pools[side], sessions[side], data)
					case <-done:
						return
					}
				}
			}()
		}
	}
	for side, tun := range tunnels {
		if err := tun.Start(); err != nil {
			t.Fatal(err)
		}
		addr, err := tun.ListenerAddr(fmt.Sprint(side + 1))
		if err != nil {
			t.Fatal(err)
		}
		// Two connections exercise both sessions in each direction.
		for range 2 {
			conn, err := net.DialTimeout("tcp", addr.String(), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err := conn.Write([]byte("pooled echo")); err != nil {
				conn.Close()
				t.Fatal(err)
			}
			got := make([]byte, 11)
			_, err = io.ReadFull(conn, got)
			conn.Close()
			if err != nil || string(got) != "pooled echo" {
				t.Fatalf("side %d echo = %q, err=%v", side, got, err)
			}
		}
	}
}
