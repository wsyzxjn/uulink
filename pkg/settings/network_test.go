package settings

import "testing"

func TestNetworkOverridesAndLimits(t *testing.T) {
	n, err := (Network{STUNServers: []string{}, MaxInFlight: 32, SessionLimit: 24, ConnectTimeoutSeconds: 7}).Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if len(n.STUNServers) != 0 || n.MaxInFlight != 32 || n.SessionLimit != 24 || n.ConnectTimeoutSeconds != 7 || n.SCTPReceiveBufferBytes != 4<<20 {
		t.Fatalf("unexpected settings: %+v", n)
	}
	for _, input := range []Network{
		{MaxInFlight: -1}, {MaxInFlight: 4097}, {SessionLimit: HardSessionLimit + 1},
		{FileBufferBytes: 1}, {STUNServers: []string{"https://example.com"}},
		{STUNServers: []string{"turn:example.com:3478"}}, {STUNServers: []string{"stun:"}},
	} {
		if _, err := input.Resolve(); err == nil {
			t.Fatalf("accepted invalid settings: %+v", input)
		}
	}
}

func TestNetworkCopiesSTUNServers(t *testing.T) {
	input := Network{STUNServers: []string{"stun:example.com:3478"}}
	a, err := input.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	a.STUNServers[0] = "changed"
	if input.STUNServers[0] != "stun:example.com:3478" {
		t.Fatal("resolution mutated input")
	}
}
