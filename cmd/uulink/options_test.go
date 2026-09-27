package main

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestPushQueueProcessesJobsAndCoalescesDuplicates(t *testing.T) {
	done := make(chan struct{})
	q := newPushQueue(done)

	started := make(chan struct{})
	release := make(chan struct{})
	if err := q.submit("first", func() {
		close(started)
		<-release
	}); err != nil {
		t.Fatalf("submit first: %v", err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first push did not start")
	}

	var ran atomic.Int32
	finished := make(chan struct{})
	if err := q.submit("same", func() { ran.Add(1) }); err != nil {
		t.Fatalf("submit duplicate 1: %v", err)
	}
	if err := q.submit("same", func() {
		ran.Add(1)
		close(finished)
	}); err != nil {
		t.Fatalf("submit duplicate 2: %v", err)
	}

	close(release)
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("coalesced push did not run")
	}
	if got := ran.Load(); got != 1 {
		t.Fatalf("coalesced jobs ran %d times, want 1", got)
	}
	stats := q.stats()
	if stats.Accepted != 2 || stats.Coalesced != 1 || stats.Rejected != 0 {
		t.Fatalf("queue stats = %+v, want accepted=2 coalesced=1 rejected=0", stats)
	}

	close(done)
	if err := q.submit("after-close", func() {}); !errors.Is(err, errPushQueueClosed) {
		t.Fatalf("submit after close error = %v, want %v", err, errPushQueueClosed)
	}
}

func TestPushQueueReportsBoundedOverflowWithoutBlocking(t *testing.T) {
	done := make(chan struct{})
	q := newPushQueue(done)

	started := make(chan struct{})
	release := make(chan struct{})
	if err := q.submit("running", func() {
		close(started)
		<-release
	}); err != nil {
		t.Fatalf("submit running: %v", err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("running push did not start")
	}
	for i := 0; i < pushQueueDepth; i++ {
		key := "queued-" + string(rune('a'+i))
		if err := q.submit(key, func() {}); err != nil {
			t.Fatalf("submit queued %d: %v", i, err)
		}
	}
	start := time.Now()
	err := q.submit("overflow", func() {})
	if !errors.Is(err, errPushQueueFull) {
		t.Fatalf("overflow submit error = %v, want %v", err, errPushQueueFull)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("overflow submit blocked for %s", elapsed)
	}
	stats := q.stats()
	if stats.Rejected != 1 {
		t.Fatalf("queue stats = %+v, want one rejected push", stats)
	}

	close(release)
	close(done)
}
