//go:build experiments

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestMixKCPRequiresCompleteExplicitDatagram(t *testing.T) {
	path := filepath.Join(t.TempDir(), "frame.bin")
	for _, data := range [][]byte{nil, make([]byte, 17), make([]byte, 65508)} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readMixKCPFrame(path); err == nil {
			t.Fatalf("accepted %d-byte datagram", len(data))
		}
	}
	want := bytes.Repeat([]byte{0x91}, 33)
	if err := os.WriteFile(path, want, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := readMixKCPFrame(path)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("datagram changed: %x, err=%v", got, err)
	}
}
