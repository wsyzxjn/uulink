package main

import (
	"context"
	"sync"

	"github.com/wsyzxjn/uulink/pkg/logging"
	"github.com/wsyzxjn/uulink/pkg/peer"
)

// Early data spares each new connection the CONNECT/SYN_ACK round trip: its
// first bytes leave right behind the CONNECT. Only a uulink peer queues such
// DATA until its target is connected; the official client relies on the
// SYN_ACK wait.
//
// The served side announces it on TEXT_DATA_CHANNEL (see expand.go) once the
// channel opens, and a uulink controller answers in kind so reverse mappings
// benefit too. The controller never speaks first, so a target running the
// official client is never sent anything new.
const earlyDataType = "early_data"

// announceEarlyData is the served side's opening message.
func announceEarlyData(ctx context.Context, p *peer.Peer) {
	select {
	case <-p.TextChannelOpen():
	case <-ctx.Done():
		return
	}
	if err := sendExpandMessage(p, &expandMessage{Type: earlyDataType}); err != nil {
		logging.Debugf("[tunnel] announce early data: %v", err)
	}
}

// earlyDataHandler calls enable once the peer announces early data. With
// answer set it replies to that first announcement.
func earlyDataHandler(p textSender, enable func(), answer bool) func([]byte) {
	var once sync.Once
	return func(data []byte) {
		msg, ok := parseExpandMessage(data)
		if !ok || msg.Type != earlyDataType {
			return
		}
		once.Do(func() {
			enable()
			logging.Infof("[tunnel] peer accepts early data; new connections skip the SYN_ACK wait")
			if !answer {
				return
			}
			if err := sendExpandMessage(p, &expandMessage{Type: earlyDataType}); err != nil {
				logging.Debugf("[tunnel] answer early data: %v", err)
			}
		})
	}
}
