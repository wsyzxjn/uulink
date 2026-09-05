package main

import (
	"encoding/hex"
	"encoding/json"
	"testing"
)

// fakeSender records what the expansion exchange writes to the peer.
type fakeSender struct{ sent [][]byte }

func (f *fakeSender) SendText(data []byte) error {
	f.sent = append(f.sent, append([]byte(nil), data...))
	return nil
}

func (f *fakeSender) last() *expandMessage {
	if len(f.sent) == 0 {
		return nil
	}
	var msg expandMessage
	if err := json.Unmarshal(f.sent[len(f.sent)-1], &msg); err != nil {
		return nil
	}
	return &msg
}

func TestParseExpandMessageRejectsOfficialTextHandshake(t *testing.T) {
	// The official client sends this protobuf frame on TEXT_DATA_CHANNEL; it
	// must never be read as a uulink control message.
	frame, err := hex.DecodeString("080410c4d8d1d4066a040a020102")
	if err != nil {
		t.Fatalf("decode handshake: %v", err)
	}
	if _, ok := parseExpandMessage(frame); ok {
		t.Fatal("official text handshake was parsed as a uulink message")
	}
}

func TestParseExpandMessageRejectsForeignJSON(t *testing.T) {
	for _, payload := range []string{
		`{"type":"expand_request","sessions":3}`, // missing version key
		`{"uulink":99,"type":"expand_request"}`,  // unknown version
		`{"uulink":1}`,                           // no type
		``,
		`not json`,
	} {
		if _, ok := parseExpandMessage([]byte(payload)); ok {
			t.Fatalf("payload %q should not parse as a uulink message", payload)
		}
	}
}

func TestParseExpandMessageAcceptsOffer(t *testing.T) {
	msg, ok := parseExpandMessage([]byte(`{"uulink":1,"type":"expand_offer","shares":[{"id":"1","code":"A"}]}`))
	if !ok {
		t.Fatal("offer did not parse")
	}
	if msg.Type != expandTypeOffer || len(msg.Shares) != 1 || msg.Shares[0].ID != "1" {
		t.Fatalf("unexpected message: %+v", msg)
	}
}

func TestNegotiatorIgnoresUnrelatedPayloads(t *testing.T) {
	n := newExpandNegotiator()
	if n.handle([]byte(`{"uulink":1,"type":"expand_request","sessions":2}`)) {
		t.Fatal("the controller must not consume its own request type")
	}
	if n.handle([]byte("garbage")) {
		t.Fatal("garbage must not be consumed")
	}
	if !n.handle([]byte(`{"uulink":1,"type":"expand_offer","shares":[{"id":"7","code":"C"}]}`)) {
		t.Fatal("offer should be consumed")
	}
	select {
	case msg := <-n.result:
		if len(msg.Shares) != 1 {
			t.Fatalf("unexpected shares: %+v", msg.Shares)
		}
	default:
		t.Fatal("offer was not delivered")
	}
}

func TestNegotiatorDropsDuplicateOffers(t *testing.T) {
	n := newExpandNegotiator()
	first := []byte(`{"uulink":1,"type":"expand_offer","shares":[{"id":"1","code":"A"}]}`)
	second := []byte(`{"uulink":1,"type":"expand_offer","shares":[{"id":"2","code":"B"}]}`)
	if !n.handle(first) {
		t.Fatal("the first offer should be recognised")
	}
	if !n.handle(second) {
		t.Fatal("the second offer should be recognised")
	}
	<-n.result
	select {
	case <-n.result:
		t.Fatal("a duplicate offer was queued")
	default:
	}
}

func TestServeExpandRequestsMintsOnlyOnce(t *testing.T) {
	calls := 0
	sender := &fakeSender{}
	handler := serveExpandRequests(sender, 3, func(extra int) ([]expandShare, error) {
		calls++
		return []expandShare{{ID: "1", Code: "A"}}, nil
	})
	// A reconnecting controller may ask twice; minting again would leak guest
	// devices, so only the first request is honoured.
	handler([]byte(`{"uulink":1,"type":"expand_request","sessions":2}`))
	handler([]byte(`{"uulink":1,"type":"expand_request","sessions":2}`))
	if calls != 1 {
		t.Fatalf("mint called %d times, want 1", calls)
	}
	if reply := sender.last(); reply == nil || reply.Type != expandTypeOffer || len(reply.Shares) != 1 {
		t.Fatalf("unexpected reply: %+v", reply)
	}
}

func TestServeExpandRequestsIgnoresNonRequests(t *testing.T) {
	handler := serveExpandRequests(&fakeSender{}, 3, func(extra int) ([]expandShare, error) {
		t.Fatal("mint must not run for an unrelated payload")
		return nil, nil
	})
	handler([]byte(`{"uulink":1,"type":"expand_offer"}`))
	handler([]byte("garbage"))
}

func TestServeExpandRequestsClampsToLocalTarget(t *testing.T) {
	var got int
	handler := serveExpandRequests(&fakeSender{}, 2, func(extra int) ([]expandShare, error) {
		got = extra
		return []expandShare{{ID: "1", Code: "A"}}, nil
	})
	handler([]byte(`{"uulink":1,"type":"expand_request","sessions":50}`))
	if got != 2 {
		t.Fatalf("extra = %d, want it clamped to the local target of 2", got)
	}
}

func TestServeExpandRequestsReportsSingleSessionConfig(t *testing.T) {
	sender := &fakeSender{}
	handler := serveExpandRequests(sender, 0, func(extra int) ([]expandShare, error) {
		t.Fatal("a single-session endpoint must not mint rooms")
		return nil, nil
	})
	handler([]byte(`{"uulink":1,"type":"expand_request","sessions":3}`))
	reply := sender.last()
	if reply == nil || reply.Type != expandTypeError {
		t.Fatalf("want an error reply, got %+v", reply)
	}
}

func TestExpansionOfferValidation(t *testing.T) {
	for _, shares := range [][]expandShare{
		{{ID: "1", Code: "A"}, {ID: "2", Code: "B"}},
		{{ID: "", Code: "A"}},
		{{ID: "1", Code: ""}},
	} {
		n := newExpandNegotiator()
		n.result <- &expandMessage{Type: expandTypeOffer, Shares: shares}
		if _, err := n.request(&fakeSender{}, 1); err == nil {
			t.Fatalf("accepted invalid offer: %+v", shares)
		}
	}
	n := newExpandNegotiator()
	n.result <- &expandMessage{Type: expandTypeOffer, Shares: []expandShare{{ID: "1", Code: "A"}, {ID: "1", Code: "A"}}}
	if _, err := n.request(&fakeSender{}, 2); err == nil {
		t.Fatal("accepted duplicate rooms")
	}
}

func TestExpansionTotalSessionLimit(t *testing.T) {
	var got int
	handler := serveExpandRequests(&fakeSender{}, 100, func(extra int) ([]expandShare, error) {
		got = extra
		return []expandShare{{ID: "1", Code: "A"}}, nil
	})
	handler([]byte(`{"uulink":1,"type":"expand_request","sessions":100}`))
	if got != 15 {
		t.Fatalf("extra rooms = %d; want 15 plus one primary", got)
	}
}
