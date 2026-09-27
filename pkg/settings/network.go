// Package settings contains shared transport settings, independent of login state.
package settings

import (
	"fmt"
	"net/url"

	"github.com/pion/stun/v3"
)

// Network uses explicit units so JSON values do not depend on Go duration units.
// Zero selects the compatibility default. Empty stun_servers disables STUN;
// an omitted/null list selects automatic discovery from the signaling gateway.
type Network struct {
	STUNServers              []string `json:"stun_servers"`
	APITimeoutSeconds        int      `json:"api_timeout_seconds,omitempty"`
	SignalingTimeoutSeconds  int      `json:"signaling_timeout_seconds,omitempty"`
	ControlAckTimeoutSeconds int      `json:"control_ack_timeout_seconds,omitempty"`
	TransportTimeoutSeconds  int      `json:"transport_timeout_seconds,omitempty"`
	ConnectTimeoutSeconds    int      `json:"connect_timeout_seconds,omitempty"`
	HalfCloseTimeoutSeconds  int      `json:"half_close_timeout_seconds,omitempty"`
	KeepAliveSeconds         int      `json:"keepalive_seconds,omitempty"`
	UDPBufferBytes           int      `json:"udp_buffer_bytes,omitempty"`
	SCTPReceiveBufferBytes   int      `json:"sctp_receive_buffer_bytes,omitempty"`
	SCTPMinCwndBytes         int      `json:"sctp_min_cwnd_bytes,omitempty"`
	SCTPRTOMaxMS             int      `json:"sctp_rto_max_ms,omitempty"`
	FileBufferBytes          int      `json:"file_buffer_bytes,omitempty"`
	FileBufferWaitSeconds    int      `json:"file_buffer_wait_seconds,omitempty"`
	MaxInFlight              int      `json:"max_in_flight,omitempty"`
	SessionLimit             int      `json:"session_limit,omitempty"`
}

const (
	DefaultMaxInFlight  = 128
	DefaultSessionLimit = 16
	// HardSessionLimit is a resource guard, including untrusted expansion requests.
	HardSessionLimit = 64
)

// Resolve validates and fills a copy; it never mutates the caller's configuration.
func (n Network) Resolve() (Network, error) {
	for _, field := range []struct {
		name              string
		value             *int
		fallback, maximum int
	}{
		{"api_timeout_seconds", &n.APITimeoutSeconds, 60, 3600},
		{"signaling_timeout_seconds", &n.SignalingTimeoutSeconds, 10, 3600},
		{"control_ack_timeout_seconds", &n.ControlAckTimeoutSeconds, 15, 3600},
		{"transport_timeout_seconds", &n.TransportTimeoutSeconds, 30, 3600},
		{"connect_timeout_seconds", &n.ConnectTimeoutSeconds, 10, 3600},
		{"half_close_timeout_seconds", &n.HalfCloseTimeoutSeconds, 60, 86400},
		{"keepalive_seconds", &n.KeepAliveSeconds, 30, 3600},
		{"udp_buffer_bytes", &n.UDPBufferBytes, 4 << 20, 64 << 20},
		{"sctp_receive_buffer_bytes", &n.SCTPReceiveBufferBytes, 4 << 20, 64 << 20},
		{"sctp_min_cwnd_bytes", &n.SCTPMinCwndBytes, 128 << 10, 16 << 20},
		{"sctp_rto_max_ms", &n.SCTPRTOMaxMS, 1500, 60000},
		{"file_buffer_bytes", &n.FileBufferBytes, 8 << 20, 64 << 20},
		{"file_buffer_wait_seconds", &n.FileBufferWaitSeconds, 30, 3600},
		{"max_in_flight", &n.MaxInFlight, DefaultMaxInFlight, 4096},
		{"session_limit", &n.SessionLimit, DefaultSessionLimit, HardSessionLimit},
	} {
		if *field.value < 0 || *field.value > field.maximum {
			return Network{}, fmt.Errorf("network.%s must be between 1 and %d, or 0 for the default", field.name, field.maximum)
		}
		if *field.value == 0 {
			*field.value = field.fallback
		}
	}
	if n.FileBufferBytes < 64<<10 {
		return Network{}, fmt.Errorf("network.file_buffer_bytes must be at least 65536")
	}
	if n.STUNServers != nil {
		n.STUNServers = append([]string{}, n.STUNServers...)
	}
	for _, server := range n.STUNServers {
		u, err := stun.ParseURI(server)
		if err != nil || (u.Scheme != stun.SchemeTypeSTUN && u.Scheme != stun.SchemeTypeSTUNS) {
			return Network{}, fmt.Errorf("network.stun_servers contains an invalid STUN URL")
		}
	}
	return n, nil
}

// DefaultSTUNServers is a last-resort compatibility list when the gateway did
// not supply usable STUN URLs. It must not be materialized into config defaults:
// doing so turns automatic discovery into an explicit override after a save.
func DefaultSTUNServers() []string {
	return []string{"stun:61.174.14.99:2580", "stun:61.153.100.69:2480", "stun:61.153.100.70:2480"}
}

// Defaults returns the validated compatibility defaults for library callers.
func Defaults() Network {
	n, _ := (Network{}).Resolve()
	return n
}

func ValidateAPIURL(raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("api_base_url must be an HTTP(S) URL without credentials, query or fragment")
	}
	return nil
}
