package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/wsyzxjn/uulink/pkg/api"
	"github.com/wsyzxjn/uulink/pkg/peer"
)

func TestRecoveryDelayForError(t *testing.T) {
	rateErr := &api.ResponseError{Code: api.CodeTooFrequent}
	for attempt := range 6 {
		delay := recoveryDelayForError(rateErr, attempt)
		minExpected := 60 * time.Second
		if delay < minExpected {
			t.Errorf("attempt %d rate limit delay = %v, want >= %v", attempt, delay, minExpected)
		}
	}
	if delay := recoveryDelayForError(rateErr, 4); delay < 15*time.Minute {
		t.Errorf("max rate limit delay = %v, want >= 15m", delay)
	}

	offlineErr := &api.ResponseError{Code: api.CodeControlledDeviceOffline}
	for attempt := range 4 {
		delay := recoveryDelayForError(offlineErr, attempt)
		minExpected := 15 * time.Second
		if delay < minExpected {
			t.Errorf("attempt %d offline delay = %v, want >= %v", attempt, delay, minExpected)
		}
	}

	genericErr := errors.New("network timeout")
	d0 := recoveryDelayForError(genericErr, 0)
	if d0 < time.Second || d0 > 2*time.Second {
		t.Errorf("attempt 0 generic delay = %v, want ~1-2s", d0)
	}
}

func TestIsPermanentError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"plain", errors.New("boom"), false},
		{"wrapped plain", fmt.Errorf("outer: %w", errors.New("boom")), false},
		{"marked", permanent(errors.New("usage")), true},
		{"marked and wrapped", fmt.Errorf("outer: %w", permanent(errors.New("usage"))), true},
		{"api transient", &api.ResponseError{Code: 5000}, false},
		{"api params", fmt.Errorf("join: %w", &api.ResponseError{Code: api.CodeInvalidParams}), true},
		{"api token expired", &api.ResponseError{Code: api.CodeTokenExpired}, true},
		{"api bad sign", &api.ResponseError{Code: api.CodeInvalidSign}, true},
		{"api wrong code is transient while the peer re-registers", &api.ResponseError{Code: api.CodeDeviceOrCodeMismatch}, false},
		{"api not found is transient", &api.ResponseError{Code: api.CodeObjectNotFound}, false},
	}
	for _, tc := range cases {
		if got := isPermanentError(tc.err); got != tc.want {
			t.Errorf("%s: isPermanentError = %v, want %v", tc.name, got, tc.want)
		}
	}
	if permanent(nil) != nil {
		t.Error("permanent(nil) should stay nil")
	}
}

func TestRecoverTunnelReturnsPermanentErrorsImmediately(t *testing.T) {
	calls := 0
	want := permanent(errors.New("bad flags"))
	start := time.Now()
	err := recoverTunnel(func(context.Context) error {
		calls++
		return want
	})
	if !errors.Is(err, want) {
		t.Fatalf("recoverTunnel() = %v, want %v", err, want)
	}
	if calls != 1 {
		t.Fatalf("run called %d times, want 1", calls)
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("recoverTunnel waited before returning a permanent error")
	}
}

func TestRecoverTunnelRetriesTransientErrors(t *testing.T) {
	calls := 0
	err := recoverTunnel(func(context.Context) error {
		calls++
		if calls < 2 {
			return errors.New("transient")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("recoverTunnel() = %v, want nil", err)
	}
	if calls != 2 {
		t.Fatalf("run called %d times, want 2", calls)
	}
}

// A P2P timeout moves the next attempt to relay. A relay session that stayed
// ready long enough and then dropped sends the attempt after it back to auto.
func TestRunWithRelayFallbackSwitchesModeAndProbesP2PAgain(t *testing.T) {
	previous := relayProbeAfter
	relayProbeAfter = 10 * time.Millisecond
	t.Cleanup(func() { relayProbeAfter = previous })

	var modes []peer.TransportMode
	err := runWithRelayFallback(peer.TransportAuto, time.Second, func(_ context.Context, mode peer.TransportMode, ready func()) error {
		modes = append(modes, mode)
		switch len(modes) {
		case 1:
			return fmt.Errorf("wrapped: %w", errP2PTimeout)
		case 2:
			ready()
			time.Sleep(2 * relayProbeAfter)
			return errTransportLost
		default:
			return nil
		}
	})
	if err != nil {
		t.Fatalf("runWithRelayFallback() = %v", err)
	}
	want := []peer.TransportMode{peer.TransportAuto, peer.TransportRelay, peer.TransportAuto}
	if fmt.Sprint(modes) != fmt.Sprint(want) {
		t.Fatalf("transport modes = %v, want %v", modes, want)
	}
}

func TestRelayFallbackNext(t *testing.T) {
	stable := relayProbeAfter
	cases := []struct {
		name     string
		initial  peer.TransportMode
		mode     peer.TransportMode
		err      error
		readyFor time.Duration
		want     peer.TransportMode
	}{
		{"p2p timeout falls back", peer.TransportAuto, peer.TransportAuto, fmt.Errorf("x: %w", errP2PTimeout), 0, peer.TransportRelay},
		{"other auto failure stays auto", peer.TransportAuto, peer.TransportAuto, errTransportLost, stable, peer.TransportAuto},
		{"relay never ready stays relay", peer.TransportAuto, peer.TransportRelay, errors.New("join failed"), 0, peer.TransportRelay},
		{"short relay session stays relay", peer.TransportAuto, peer.TransportRelay, errTransportLost, stable / 2, peer.TransportRelay},
		{"stable relay session probes p2p", peer.TransportAuto, peer.TransportRelay, errTransportLost, stable, peer.TransportAuto},
		{"explicit relay is kept", peer.TransportRelay, peer.TransportRelay, errTransportLost, 10 * stable, peer.TransportRelay},
	}
	for _, tc := range cases {
		f := &relayFallback{initial: tc.initial, mode: tc.mode, p2pTimeout: time.Second}
		f.next(tc.err, tc.readyFor)
		if f.mode != tc.want {
			t.Errorf("%s: mode = %s, want %s", tc.name, f.mode, tc.want)
		}
	}
}

// A signal during a connection attempt must end the attempt through ctx and
// stop the recovery loop, instead of letting the attempt run to completion.
func TestRecoverTunnelStopsOnInterrupt(t *testing.T) {
	started := make(chan struct{})
	calls := 0
	done := make(chan error, 1)
	go func() {
		done <- recoverTunnel(func(ctx context.Context) error {
			calls++
			close(started)
			<-ctx.Done()
			return errors.New("attempt aborted")
		})
	}()
	<-started
	if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
		t.Fatalf("send SIGINT: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("recoverTunnel() = %v, want nil after interrupt", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("recoverTunnel did not stop after SIGINT")
	}
	if calls != 1 {
		t.Fatalf("run called %d times, want 1", calls)
	}
}
