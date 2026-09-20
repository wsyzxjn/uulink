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

func TestRunWithRelayFallbackSwitchesModeAfterP2PTimeout(t *testing.T) {
	var modes []peer.TransportMode
	err := runWithRelayFallback(peer.TransportAuto, time.Second, func(_ context.Context, mode peer.TransportMode) error {
		modes = append(modes, mode)
		if mode == peer.TransportAuto {
			return fmt.Errorf("wrapped: %w", errP2PTimeout)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("runWithRelayFallback() = %v", err)
	}
	if len(modes) != 2 || modes[0] != peer.TransportAuto || modes[1] != peer.TransportRelay {
		t.Fatalf("transport modes = %v, want [auto relay]", modes)
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
