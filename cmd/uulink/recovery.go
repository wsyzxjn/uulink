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

	"github.com/wsyzxjn/uulink/pkg/api"
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
	if attempt > 6 {
		attempt = 6
	}
	if attempt < 0 {
		attempt = 0
	}
	base := min(time.Second*time.Duration(1<<attempt), 60*time.Second)
	return min(base+time.Duration(rand.Int64N(int64(base/5)+1)), 60*time.Second)
}

func recoveryDelayForError(err error, attempt int) time.Duration {
	var respErr *api.ResponseError
	if errors.As(err, &respErr) {
		switch respErr.Code {
		case api.CodeTooFrequent:
			// Rate limit cool-down: NetEase risk control penalty windows can last
			// 10-15 minutes. Back off up to 15 minutes to allow the penalty window
			// to naturally expire without continuous client resets.
			delays := [...]time.Duration{
				1 * time.Minute,
				2 * time.Minute,
				5 * time.Minute,
				10 * time.Minute,
				15 * time.Minute,
			}
			idx := min(attempt, len(delays)-1)
			base := delays[idx]
			return base + time.Duration(rand.Int64N(int64(15*time.Second)+1))
		case api.CodeControlledDeviceOffline:
			// When the target device is offline, back off further (up to 5 minutes)
			// to avoid hammering the API during long peer WAN outages.
			delays := [...]time.Duration{
				15 * time.Second,
				30 * time.Second,
				1 * time.Minute,
				2 * time.Minute,
				5 * time.Minute,
			}
			idx := min(attempt, len(delays)-1)
			base := delays[idx]
			return base + time.Duration(rand.Int64N(int64(10*time.Second)+1))
		}
	}
	return recoveryDelay(attempt)
}

// permanentError marks a failure that a retry cannot fix: bad flags or
// configuration, or an API answer that says the request itself is wrong.
// recoverTunnel returns such errors instead of looping on them.
type permanentError struct{ err error }

func (e *permanentError) Error() string { return e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }

// permanent wraps err so recoverTunnel does not retry it.
func permanent(err error) error {
	if err == nil {
		return nil
	}
	return &permanentError{err: err}
}

// isPermanentError reports whether err was marked permanent or carries an API
// business code that only new input or fresh credentials can clear.
func isPermanentError(err error) bool {
	var perm *permanentError
	if errors.As(err, &perm) {
		return true
	}
	var response *api.ResponseError
	return errors.As(err, &response) && response.Permanent()
}

// recoverTunnel keeps transient API/signaling/transport errors from exiting a
// standalone process. Each attempt owns and closes its previous resources.
//
// ctx is cancelled by SIGINT/SIGTERM; run must return promptly once it is
// done. Permanent errors (see isPermanentError) end the loop and are returned
// so the process exits non-zero instead of retrying forever.
func recoverTunnel(run func(ctx context.Context) error) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// The first signal cancels ctx, which ends every wait inside run. A second
	// signal must be able to kill a process stuck in a call that cannot be
	// cancelled, so restore the default handling once ctx is done.
	go func() {
		<-ctx.Done()
		stop()
	}()
	for attempt := 0; ; attempt++ {
		start := time.Now()
		err := run(ctx)
		if err == nil || ctx.Err() != nil {
			return nil
		}
		if isPermanentError(err) {
			return err
		}
		if time.Since(start) > time.Minute {
			attempt = 0
		}
		delay := recoveryDelayForError(err, attempt)
		logging.Warnf("[recovery] %v; reconnecting in %s", err, delay.Round(time.Millisecond))
		if !waitRecovery(ctx, delay) {
			return nil
		}
	}
}

// relayProbeAfter is how long a relay session has to stay ready before the
// next reconnect probes a direct P2P connection again. It matches the
// one-minute threshold recoverTunnel uses to call an attempt healthy.
var relayProbeAfter = time.Minute

// runWithRelayFallback runs a controller under recoverTunnel. When a P2P
// attempt times out in auto mode, the next attempts require a TURN relay.
// The fallback is not permanent: once a relay session has stayed ready for
// relayProbeAfter, the reconnect after it starts from the initial mode again,
// because the conditions that forced the relay may have changed since.
//
// run calls ready when its transport is ready; later calls are ignored.
func runWithRelayFallback(initial peer.TransportMode, p2pTimeout time.Duration, run func(ctx context.Context, mode peer.TransportMode, ready func()) error) error {
	fallback := &relayFallback{initial: initial, mode: initial, p2pTimeout: p2pTimeout}
	return recoverTunnel(func(ctx context.Context) error {
		var readyAt atomic.Int64
		err := run(ctx, fallback.mode, func() { readyAt.CompareAndSwap(0, time.Now().UnixNano()) })
		// A clean exit, a shutdown or a permanent error ends recoverTunnel, so
		// there is no next attempt to choose a mode for.
		if err == nil || ctx.Err() != nil || isPermanentError(err) {
			return err
		}
		var readyFor time.Duration
		if at := readyAt.Load(); at != 0 {
			readyFor = time.Since(time.Unix(0, at))
		}
		fallback.next(err, readyFor)
		return err
	})
}

// relayFallback holds the transport mode of the next controller attempt.
type relayFallback struct {
	initial    peer.TransportMode
	mode       peer.TransportMode
	p2pTimeout time.Duration
}

// next picks the mode for the attempt after one that failed with err and
// whose transport stayed ready for readyFor (zero if it never was ready).
func (f *relayFallback) next(err error, readyFor time.Duration) {
	switch {
	case errors.Is(err, errP2PTimeout) && f.mode == peer.TransportAuto:
		logging.Warnf("[peer] P2P punch-through timed out after %s; falling back to relay transport", f.p2pTimeout)
		f.mode = peer.TransportRelay
	case f.mode != f.initial && readyFor >= relayProbeAfter:
		logging.Infof("[peer] relay session ended after %s; the next attempt probes a direct P2P connection again", readyFor.Round(time.Second))
		f.mode = f.initial
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
			delay = recoveryDelayForError(err, attempt)
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
