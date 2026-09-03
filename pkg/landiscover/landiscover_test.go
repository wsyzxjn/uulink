package landiscover

import (
	"testing"
	"time"
)

func TestFormatMessage(t *testing.T) {
	msg := FormatMessage("Test Server", 25565)
	expected := "[MOTD]Test Server[/MOTD][AD]25565[/AD]"
	if msg != expected {
		t.Fatalf("FormatMessage = %q, want %q", msg, expected)
	}
}

func TestStartInvalidPort(t *testing.T) {
	if _, err := Start("Test", -1, time.Second); err == nil {
		t.Fatal("expected error on negative port, got nil")
	}
	if _, err := Start("Test", 70000, time.Second); err == nil {
		t.Fatal("expected error on port > 65535, got nil")
	}
}

func TestStartAndStop(t *testing.T) {
	s, err := Start("Smoke Test", 25565, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	s.Stop()
}
