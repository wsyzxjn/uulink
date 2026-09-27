package signaling

import (
	"encoding/json"
	"sync"
	"testing"
	"time"
)

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
