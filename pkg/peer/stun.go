package peer

import (
	"github.com/wsyzxjn/uulink/pkg/logging"
	"github.com/wsyzxjn/uulink/pkg/settings"
	"github.com/wsyzxjn/uulink/pkg/signaling"
)

func (p *Peer) handleControlledInfo(ev *signaling.Event) {
	info, err := signaling.ParseControlledInfo(ev)
	p.soacMu.Lock()
	defer p.soacMu.Unlock()
	// A malformed/empty new event must not leave an old controller's list active.
	p.controlledInfo = info
	if err != nil {
		logging.Debugf("[peer] invalid be-controlled ICE metadata; keeping fallback available")
		return
	}
	logging.Debugf("[peer] received controlled STUN metadata: servers=%d", len(info.STUNServers))
}

// controlledSTUNServers selects URLs when answering an offer, with soacMu held.
// Explicit config (including []) wins. Metadata must match every connection
// identifier it supplies, so a prior controller's list cannot leak into a new one.
func (p *Peer) controlledSTUNServers(offer soacEvent) ([]string, string) {
	if p.network.STUNServers != nil {
		return p.network.STUNServers, "config"
	}
	if info := p.controlledInfo; info != nil && len(info.STUNServers) > 0 &&
		(info.ClientID == "" || info.ClientID == offer.ClientID) &&
		(info.IceID == "" || info.IceID == offer.Data.IceID) &&
		(info.AppControlID == "" || info.AppControlID == offer.Data.AppControlID) {
		return info.STUNServers, "be-controlled"
	}
	if len(p.roomSTUNServers) > 0 {
		return p.roomSTUNServers, "room_info"
	}
	return settings.DefaultSTUNServers(), "fallback"
}
