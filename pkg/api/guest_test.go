package api

import (
	"strings"
	"testing"
)

func TestGenerateSharePassCode(t *testing.T) {
	seen := make(map[string]struct{})
	for i := 0; i < 100; i++ {
		code, err := GenerateSharePassCode()
		if err != nil {
			t.Fatalf("GenerateSharePassCode: %v", err)
		}
		if len(code) != 8 {
			t.Fatalf("code length = %d, want 8", len(code))
		}
		for _, r := range code {
			if !strings.ContainsRune(sharePassCodeAlphabet, r) {
				t.Fatalf("code %q contains rune %q outside alphabet", code, r)
			}
		}
		seen[code] = struct{}{}
	}
	if len(seen) < 90 {
		t.Fatalf("generated only %d distinct codes from 100 attempts", len(seen))
	}
}

func TestSharePassCodeSign(t *testing.T) {
	const (
		controlID = "12345678"
		passCode  = "ABCDEFGH"
	)
	const want = "1bd34f9851a94e1dcff013944f1604d4bdf77fb1cbcda393678dc0b9db76f0d6"
	if got := SharePassCodeSign(controlID, passCode); got != want {
		t.Fatalf("SharePassCodeSign() = %q, want %q", got, want)
	}
}
