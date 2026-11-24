package main

import (
	"encoding/json"
	"testing"

	"github.com/wsyzxjn/uulink/pkg/proto/gvpb"
)

func earlyDataMessage(t *testing.T, msgType string) []byte {
	t.Helper()
	data, err := json.Marshal(&expandMessage{UULink: expandProtocolVersion, Type: msgType})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// The controller enables early data on the served side's announcement and
// answers it exactly once; nothing else on the channel turns it on.
func TestControllerAnswersEarlyDataAnnouncementOnce(t *testing.T) {
	sender := &fakeSender{}
	enabled := 0
	handle := earlyDataHandler(sender, func() { enabled++ }, true)

	handle(gvpb.TextHandshake(1, 1))
	handle(earlyDataMessage(t, expandTypeOffer))
	if enabled != 0 || len(sender.sent) != 0 {
		t.Fatalf("unrelated messages enabled early data (%d) or were answered (%d)", enabled, len(sender.sent))
	}

	handle(earlyDataMessage(t, earlyDataType))
	handle(earlyDataMessage(t, earlyDataType))
	if enabled != 1 {
		t.Fatalf("enable called %d times, want 1", enabled)
	}
	if len(sender.sent) != 1 || sender.last().Type != earlyDataType {
		t.Fatalf("want one early_data answer, got %d message(s)", len(sender.sent))
	}
}

// The served side spoke first, so it enables early data on the answer without
// replying again.
func TestServedSideEnablesEarlyDataOnAnswer(t *testing.T) {
	sender := &fakeSender{}
	enabled := 0
	handle := earlyDataHandler(sender, func() { enabled++ }, false)

	handle(earlyDataMessage(t, earlyDataType))
	if enabled != 1 || len(sender.sent) != 0 {
		t.Fatalf("enabled %d time(s) and sent %d message(s), want 1 and 0", enabled, len(sender.sent))
	}
}
