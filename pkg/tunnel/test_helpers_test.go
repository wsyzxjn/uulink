package tunnel

import (
	"fmt"
	"testing"
	"time"
)

type channelSender struct {
	ch   chan []byte
	done chan struct{}
}

func newChannelSender() *channelSender {
	return &channelSender{ch: make(chan []byte, 64), done: make(chan struct{})}
}

func (s *channelSender) SendFrame(msg []byte) error {
	select {
	case s.ch <- msg:
		return nil
	case <-s.done:
		return fmt.Errorf("sender closed")
	}
}

func (s *channelSender) Close() {
	select {
	case <-s.done:
	default:
		close(s.done)
	}
}

func (s *channelSender) Forward(t *Tunnel) {
	go func() {
		for {
			select {
			case msg := <-s.ch:
				t.HandleMessage(msg)
			case <-s.done:
				return
			}
		}
	}()
}

func receiveFrame(t *testing.T, ch chan []byte) []byte {
	t.Helper()
	select {
	case msg := <-ch:
		return msg
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for PM frame")
		return nil
	}
}
