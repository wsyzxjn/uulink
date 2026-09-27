package tunnel

import (
	"testing"
	"time"

	"github.com/wsyzxjn/uulink/pkg/settings"
)

func TestConfiguredHalfCloseTimeout(t *testing.T) {
	tun, err := NewTunnelWithSettings(nil, nil, settings.Network{HalfCloseTimeoutSeconds: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Stop()
	s := tun.newStream("1", "1", nil)
	tun.streams.Store(streamKey("1", "1"), s)
	s.localFinSent = true
	s.armHalfCloseTimeout()
	select {
	case <-s.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("configured half-close deadline was ignored")
	}
}

func TestMessageSequenceDoesNotRepeatCaptureNumbers(t *testing.T) {
	seen := map[string]bool{}
	for range 12 {
		seq := nextSeq()
		if seen[seq] {
			t.Fatalf("repeated message sequence %s", seq)
		}
		seen[seq] = true
	}
}
