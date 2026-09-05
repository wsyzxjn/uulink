package peer

import (
	"sync"
	"testing"
)

// A controller may speak as soon as TEXT_DATA_CHANNEL opens, which can happen
// before the controlled side finishes wiring its handler. Those messages have
// to survive the gap, otherwise pool expansion silently never happens.
func TestOnTextMessageReplaysEarlyMessages(t *testing.T) {
	p := &Peer{}
	p.handleTextMessage([]byte("first"))
	p.handleTextMessage([]byte("second"))

	var got []string
	p.OnTextMessage(func(data []byte) { got = append(got, string(data)) })

	if len(got) != 2 || got[0] != "first" || got[1] != "second" {
		t.Fatalf("early messages were not replayed in order: %v", got)
	}

	p.handleTextMessage([]byte("third"))
	if len(got) != 3 || got[2] != "third" {
		t.Fatalf("later message was not delivered: %v", got)
	}
}

func TestPendingTextIsBounded(t *testing.T) {
	p := &Peer{}
	for i := 0; i < maxPendingText*4; i++ {
		p.handleTextMessage([]byte("x"))
	}
	count := 0
	p.OnTextMessage(func([]byte) { count++ })
	if count != maxPendingText {
		t.Fatalf("replayed %d messages, want the buffer capped at %d", count, maxPendingText)
	}
}

func TestHandleTextMessageIsConcurrencySafe(t *testing.T) {
	p := &Peer{}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.handleTextMessage([]byte("m"))
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		p.OnTextMessage(func([]byte) {})
	}()
	wg.Wait()
}
