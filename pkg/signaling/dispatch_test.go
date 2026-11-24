package signaling

import (
	"encoding/json"
	"sync"
	"testing"
	"time"
)

func TestSpliceAttachmentRejectsInvalidIndex(t *testing.T) {
	for _, raw := range []string{
		`{"_placeholder":true,"num":-1}`,
		`{"_placeholder":true,"num":0.5}`,
		`{"_placeholder":true,"num":1}`,
		`{"_placeholder":true,"num":1e100}`,
		`{"_placeholder":true}`,
	} {
		t.Run(raw, func(t *testing.T) {
			if got := spliceAttachment(json.RawMessage(raw), [][]byte{[]byte("SDP")}); string(got) != raw {
				t.Fatalf("invalid placeholder replaced with %s", got)
			}
		})
	}
	got := spliceAttachment(json.RawMessage(`{"_placeholder":true,"num":0}`), [][]byte{[]byte("SDP")})
	var decoded []byte
	if err := json.Unmarshal(got, &decoded); err != nil || string(decoded) != "SDP" {
		t.Fatalf("valid attachment = %s, err = %v", got, err)
	}
}

func TestDispatchEventPreservesOrderOffReadLoop(t *testing.T) {
	done := make(chan struct{})
	c := &Client{
		done:       done,
		eventQueue: make(chan *Event, eventQueueDepth),
		handlers:   make(map[string]func(*Event)),
	}
	var mu sync.Mutex
	var got []string
	c.handlers["ordered"] = func(ev *Event) {
		mu.Lock()
		got = append(got, ev.Name+string(ev.Args[0]))
		mu.Unlock()
	}
	go c.dispatchLoop()

	c.dispatchEvent(&Event{Name: "ordered", Args: []json.RawMessage{json.RawMessage("-1")}})
	c.dispatchEvent(&Event{Name: "ordered", Args: []json.RawMessage{json.RawMessage("-2")}})

	deadline := time.Now().Add(time.Second)
	for {
		mu.Lock()
		complete := len(got) == 2
		mu.Unlock()
		if complete {
			break
		}
		if time.Now().After(deadline) {
			mu.Lock()
			snapshot := append([]string(nil), got...)
			mu.Unlock()
			t.Fatalf("dispatch results = %v, want two ordered events", snapshot)
		}
		time.Sleep(time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if got[0] != "ordered-1" || got[1] != "ordered-2" {
		t.Fatalf("dispatch order = %v, want [ordered-1 ordered-2]", got)
	}
	close(done)
}
