package main

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/wsyzxjn/uulink/pkg/auth"
	"github.com/wsyzxjn/uulink/pkg/logging"
	"github.com/wsyzxjn/uulink/pkg/peer"
	"github.com/wsyzxjn/uulink/pkg/tunnel"
)

var sessionGeneration atomic.Uint64
var errTransportLost = errors.New("transport disconnected")

const disconnectGrace = 10 * time.Second

func nextSessionID(base string) string { return fmt.Sprintf("%s-g%d", base, sessionGeneration.Add(1)) }

func waitRecovery(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func recoveryDelay(attempt int) time.Duration {
	if attempt > 5 {
		attempt = 5
	}
	if attempt < 0 {
		attempt = 0
	}
	base := min(time.Second*time.Duration(1<<attempt), 30*time.Second)
	return min(base+time.Duration(rand.Int64N(int64(base/5)+1)), 30*time.Second)
}

// recoverTunnel keeps transient API/signaling/transport errors from exiting a
// standalone process. Each attempt owns and closes its previous resources.
func recoverTunnel(configPath string, cfg *auth.Config, run func() error) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	for attempt := 0; ; attempt++ {
		start := time.Now()
		err := run()
		if err == nil || ctx.Err() != nil {
			return nil
		}
		if time.Since(start) > time.Minute {
			attempt = 0
		}
		delay := recoveryDelay(attempt)
		logging.Warnf("[recovery] %v; reconnecting in %s", err, delay.Round(time.Millisecond))
		if !waitRecovery(ctx, delay) {
			return nil
		}

	}
}

// lostTransport tolerates a short disconnected interval but not a failed or
// closed peer. A remote replacement offer also requires a fresh room handshake.
func lostTransport(p *peer.Peer, since *time.Time, now time.Time) bool {
	select {
	case <-p.RestartRequested():
		return true
	default:
	}
	state := p.ConnectionState()
	switch state {
	case "failed", "closed":
		return true
	case "disconnected":
		if since.IsZero() {
			*since = now
		}
		return now.Sub(*since) >= disconnectGrace
	default:
		*since = time.Time{}
	}
	return false
}

func monitorSession(set *sessionSet, rt *sessionRuntime, tun *tunnel.Tunnel, pool *tunnel.SessionPool) {
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		var since time.Time
		for {
			select {
			case <-set.ctx.Done():
				return
			case <-rt.done:
				return
			case <-rt.sig.Done():
				logging.Warnf("[recovery] %s signaling lost", rt.id)
				rt.close()
				set.remove(rt.id)
				return
			case now := <-ticker.C:
				if lostTransport(rt.peer, &since, now) {
					logging.Warnf("[recovery] %s transport lost", rt.id)
					set.remove(rt.id)
					rt.close()
					return
				}
			}
		}
	}()
}

func monitorPrimary(ctx context.Context, p *peer.Peer, failures chan<- error) {
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		var since time.Time
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				if lostTransport(p, &since, now) {
					select {
					case failures <- errTransportLost:
					case <-ctx.Done():
					}
					return
				}
			}
		}
	}()
}

// reconcileLoop serializes repairs and backs off failed attempts. A healthy
// pool is checked every five seconds; shutdown interrupts both kinds of wait.
func reconcileLoop(ctx context.Context, step func(context.Context) error) error {
	for attempt := 0; ; {
		if ctx.Err() != nil {
			return nil
		}
		err := step(ctx)
		delay := 5 * time.Second
		if err != nil {
			delay = recoveryDelay(attempt)
			attempt++
			logging.Warnf("[recovery] %v; retry in %s", err, delay.Round(time.Millisecond))
		} else {
			attempt = 0
		}
		if !waitRecovery(ctx, delay) {
			return nil
		}
	}
}
