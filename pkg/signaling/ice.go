package signaling

import (
	"encoding/json"
	"fmt"

	"github.com/pion/stun/v3"
)

// ControlledInfo is the connection-scoped metadata sent to the publisher.
// Keep only public STUN URLs, never TURN credentials from the control event.
type ControlledInfo struct {
	ClientID     string
	IceID        string
	AppControlID string
	STUNServers  []string
}

type controlledEnvelope struct {
	ClientID     string              `json:"client_id"`
	IceID        string              `json:"ice_id"`
	AppControlID string              `json:"app_control_id"`
	ICEServers   json.RawMessage     `json:"iceServers"`
	Data         *controlledEnvelope `json:"data"`
}

// ParseControlledInfo accepts direct metadata and the data envelope used by
// signaling messages. Only one wrapper level is considered, not arbitrary
// nested objects which may contain a different connection's ICE credentials.
func ParseControlledInfo(ev *Event) (*ControlledInfo, error) {
	if len(ev.Args) == 0 || len(ev.Args[0]) > 64<<10 {
		return nil, fmt.Errorf("invalid be-controlled event size")
	}
	var raw controlledEnvelope
	if err := json.Unmarshal(ev.Args[0], &raw); err != nil {
		return nil, fmt.Errorf("invalid be-controlled metadata")
	}
	if raw.Data != nil {
		data := raw.Data
		if len(raw.ICEServers) == 0 {
			raw.ICEServers = data.ICEServers
		}
		if raw.ClientID == "" {
			raw.ClientID = data.ClientID
		}
		if raw.IceID == "" {
			raw.IceID = data.IceID
		}
		if raw.AppControlID == "" {
			raw.AppControlID = data.AppControlID
		}
	}
	return &ControlledInfo{ClientID: raw.ClientID, IceID: raw.IceID, AppControlID: raw.AppControlID, STUNServers: stunServersFromJSON(raw.ICEServers)}, nil
}

// UU uses string URLs, while Pion's ICE JSON decoder accepts only arrays. Adapt
// those two JSON shapes with encoding/json, then reuse Pion's STUN URI parser.
// Malformed entries cannot poison the remaining valid entries. TURN credentials
// are not decoded. Bound the list supplied over the network.
func stunServersFromJSON(raw json.RawMessage) []string {
	if len(raw) == 0 || len(raw) > 64<<10 {
		return nil
	}
	var entries []json.RawMessage
	if json.Unmarshal(raw, &entries) != nil || len(entries) > 64 {
		return nil
	}
	var urls []string
	seen := make(map[string]bool)
	for _, entry := range entries {
		var server struct {
			URLs json.RawMessage `json:"urls"`
		}
		if json.Unmarshal(entry, &server) != nil {
			continue
		}
		var candidates []string
		var single string
		if json.Unmarshal(server.URLs, &single) == nil {
			candidates = []string{single}
		} else if json.Unmarshal(server.URLs, &candidates) != nil {
			continue
		}
		for _, rawURL := range candidates {
			u, err := stun.ParseURI(rawURL)
			if err != nil || (u.Scheme != stun.SchemeTypeSTUN && u.Scheme != stun.SchemeTypeSTUNS) {
				continue
			}
			value := u.String()
			if seen[value] {
				continue
			}
			seen[value] = true
			urls = append(urls, value)
			if len(urls) == 64 {
				return urls
			}
		}
	}
	return urls
}
