package peer

import (
	"fmt"
	"strings"

	"github.com/pion/webrtc/v4"
)

// TransportMode is the session-level WebRTC transport policy selected by the
// controller. A server requirement can upgrade auto to relay, but cannot be
// downgraded by local configuration.
type TransportMode string

const (
	// TransportAuto allows direct and relay candidates.
	TransportAuto TransportMode = "auto"
	// TransportRelay allows only TURN relay candidates.
	TransportRelay TransportMode = "relay"
)

// ParseTransportMode parses the CLI transport value.
func ParseTransportMode(value string) (TransportMode, error) {
	switch TransportMode(value) {
	case TransportAuto, TransportRelay:
		return TransportMode(value), nil
	default:
		return "", fmt.Errorf("invalid transport mode %q (want auto or relay)", value)
	}
}

// String returns the canonical mode, treating the zero value as auto.
func (m TransportMode) String() string {
	if m == "" {
		return string(TransportAuto)
	}
	return string(m)
}

// resolveTransportMode combines the controller preference with the server
// requirement. The server requirement is authoritative.
func resolveTransportMode(local TransportMode, serverRequiresRelay bool) TransportMode {
	if serverRequiresRelay {
		return TransportRelay
	}
	if local == "" {
		return TransportAuto
	}
	return local
}

// hasTURNServer reports whether at least one ICE server is a TURN endpoint.
func hasTURNServer(servers []webrtc.ICEServer) bool {
	for _, server := range servers {
		for _, rawURL := range server.URLs {
			lower := strings.ToLower(strings.TrimSpace(rawURL))
			if strings.HasPrefix(lower, "turn:") || strings.HasPrefix(lower, "turns:") {
				return true
			}
		}
	}
	return false
}

func transportICEPolicy(mode TransportMode) webrtc.ICETransportPolicy {
	if resolveTransportMode(mode, false) == TransportRelay {
		return webrtc.ICETransportPolicyRelay
	}
	return webrtc.ICETransportPolicyAll
}
