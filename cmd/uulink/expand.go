package main

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/wsyzxjn/uulink/pkg/api"
	"github.com/wsyzxjn/uulink/pkg/auth"
	"github.com/wsyzxjn/uulink/pkg/logging"
	"github.com/wsyzxjn/uulink/pkg/peer"
	"github.com/wsyzxjn/uulink/pkg/tunnel"
)

// Relayed sessions are rate limited per TURN allocation, so a pooled tunnel
// only gains bandwidth when each session owns a separate allocation. The
// controller therefore negotiates the extra rooms in band once it sees that the
// primary session landed on a relay, which keeps the published share stable and
// spares the operator from copying a list of share codes between hosts.
//
// The exchange runs over TEXT_DATA_CHANNEL, which the official client uses only
// for a fixed protobuf handshake. Every uulink message is JSON carrying the
// "uulink" version key, so a frame from an official peer is never mistaken for
// one of ours and vice versa.

const (
	expandProtocolVersion = 1

	expandTypeRequest = "expand_request"
	expandTypeOffer   = "expand_offer"
	expandTypeError   = "expand_error"

	// expandOfferTimeout bounds the wait for the peer's reply. Minting a guest
	// room involves several API round trips per session.
	expandOfferTimeout = 90 * time.Second

	// maxExpandSessions caps what a peer may ask us to create, so a buggy or
	// hostile controller cannot make us mint rooms without bound. The default
	// target remains four; this upper bound allows explicit high-session tests.
	maxExpandSessions = maxRelaySessions - 1

	// expandChannelTimeout bounds the wait for the control channel to open.
	expandChannelTimeout = 30 * time.Second
)

// expandMessage is the wire format of the in-band pool expansion exchange.
type expandMessage struct {
	UULink   int           `json:"uulink"`
	Type     string        `json:"type"`
	Sessions int           `json:"sessions,omitempty"`
	Shares   []expandShare `json:"shares,omitempty"`
	Message  string        `json:"message,omitempty"`
}

// expandShare is one additional room the controller may join.
type expandShare struct {
	ID   string `json:"id"`
	Code string `json:"code"`
}

// parseExpandMessage decodes a TEXT_DATA_CHANNEL payload. It reports false for
// anything that is not a uulink control message, including the official
// client's protobuf handshake.
func parseExpandMessage(data []byte) (*expandMessage, bool) {
	if len(data) == 0 || data[0] != '{' {
		return nil, false
	}
	var msg expandMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, false
	}
	if msg.UULink != expandProtocolVersion || msg.Type == "" {
		return nil, false
	}
	return &msg, true
}

// textSender is the half of *peer.Peer the expansion exchange needs, so the
// protocol can be exercised without a live WebRTC connection.
type textSender interface {
	SendText(data []byte) error
}

func sendExpandMessage(p textSender, msg *expandMessage) error {
	msg.UULink = expandProtocolVersion
	payload, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("encode %s: %w", msg.Type, err)
	}
	if err := p.SendText(payload); err != nil {
		return fmt.Errorf("send %s: %w", msg.Type, err)
	}
	return nil
}

// expandNegotiator collects the peer's reply to one expansion request.
type expandNegotiator struct {
	mu     sync.Mutex
	result chan *expandMessage
}

func newExpandNegotiator() *expandNegotiator {
	return &expandNegotiator{result: make(chan *expandMessage, 1)}
}

// handle feeds a TEXT_DATA_CHANNEL payload to the negotiator and reports
// whether it belonged to the expansion exchange.
func (n *expandNegotiator) handle(data []byte) bool {
	msg, ok := parseExpandMessage(data)
	if !ok {
		return false
	}
	switch msg.Type {
	case expandTypeOffer, expandTypeError:
		n.mu.Lock()
		defer n.mu.Unlock()
		select {
		case n.result <- msg:
		default:
			logging.Debugf("[expand] dropping duplicate %s", msg.Type)
		}
		return true
	}
	return false
}

// request asks the peer for extra sessions and returns the offered rooms.
func (n *expandNegotiator) request(p textSender, extra int) ([]expandShare, error) {
	if err := sendExpandMessage(p, &expandMessage{Type: expandTypeRequest, Sessions: extra}); err != nil {
		return nil, err
	}
	select {
	case msg := <-n.result:
		if msg.Type == expandTypeError {
			return nil, fmt.Errorf("peer declined to expand the pool: %s", msg.Message)
		}
		if len(msg.Shares) == 0 {
			return nil, fmt.Errorf("peer offered no additional rooms")
		}
		if len(msg.Shares) > extra || len(msg.Shares) > maxExpandSessions {
			return nil, fmt.Errorf("peer offered too many additional rooms")
		}
		seen := make(map[string]bool, len(msg.Shares))
		for _, share := range msg.Shares {
			if share.ID == "" || share.Code == "" || seen[share.ID] {
				return nil, fmt.Errorf("peer offered an empty or duplicate room")
			}
			seen[share.ID] = true
		}
		return msg.Shares, nil
	case <-time.After(expandOfferTimeout):
		return nil, fmt.Errorf("peer did not answer the expansion request within %s", expandOfferTimeout)
	}
}

// expandMinter creates the extra rooms on the served side. It returns the
// shares a controller may join, and is expected to be safe to call once.
type expandMinter func(extra int) ([]expandShare, error)

// serveExpandRequests answers expansion requests from the controller. Only the
// first request is honoured: the pool is sized once, and re-minting rooms on
// every request would let a reconnect loop leak guest devices.
func serveExpandRequests(p textSender, maxExtra int, mint expandMinter) func([]byte) {
	var once sync.Once
	return func(data []byte) {
		msg, ok := parseExpandMessage(data)
		if !ok || msg.Type != expandTypeRequest {
			return
		}
		once.Do(func() {
			extra := msg.Sessions
			if extra > maxExtra {
				extra = maxExtra
			}
			if extra > maxExpandSessions {
				extra = maxExpandSessions
			}
			if extra <= 0 {
				_ = sendExpandMessage(p, &expandMessage{
					Type:    expandTypeError,
					Message: "this endpoint is configured for a single session",
				})
				return
			}
			logging.Infof("[expand] controller requested %d additional session(s)", extra)
			shares, err := mint(extra)
			if err != nil {
				logging.Errorf("[expand] could not create additional rooms: %v", err)
				_ = sendExpandMessage(p, &expandMessage{Type: expandTypeError, Message: err.Error()})
				return
			}
			if err := sendExpandMessage(p, &expandMessage{Type: expandTypeOffer, Shares: shares}); err != nil {
				logging.Errorf("[expand] could not send the room offer: %v", err)
				return
			}
			logging.Infof("[expand] offered %d additional room(s) to the controller", len(shares))
		})
	}
}

// mintExpansionRooms creates extra guest rooms on the served side and attaches
// each one to the running tunnel, so the controller can spread streams over
// several TURN allocations. Rooms that fail to come up are skipped rather than
// failing the whole request: a smaller pool still beats a single session.
func mintExpansionRooms(cfg *auth.Config, tun *tunnel.Tunnel, pool *tunnel.AdaptiveSessionPool, set *sessionSet, shareOptions guestShareOptions, policy tunnel.SecurityPolicy, extra int) ([]expandShare, error) {
	hostname, err := cfg.EffectiveHostname()
	if err != nil {
		return nil, fmt.Errorf("resolve hostname: %w", err)
	}

	// Each pooled room needs its own accountless device, so the identity of the
	// published share is never reused or disturbed.
	roomOptions := shareOptions
	roomOptions.ConfigPath = ""
	roomOptions.PublishURL = ""

	// Registering a guest device, creating its room and waiting for the connect
	// ID costs several seconds each, so the rooms are prepared concurrently.
	// The tunnel keeps serving on its primary session throughout.
	type mintResult struct {
		share expandShare
		err   error
	}
	results := make([]mintResult, extra)
	var wg sync.WaitGroup
	for index := range extra {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sessionID := fmt.Sprintf("expand-%d", index+1)
			sessionCfg := *cfg
			sessionCfg.UnboundClientID = ""
			sessionCfg.UnboundDeviceID = ""
			sessionCfg.CustomCode = ""
			sessionCfg.ShareID = ""

			rt, share, err := startPooledGuestServer(api.NewClient(&sessionCfg), tun, pool, set, sessionID,
				fmt.Sprintf("%s-x%d", hostname, index+1), roomOptions, nil, policy)
			if err != nil {
				results[index] = mintResult{err: err}
				return
			}
			set.add(rt)
			results[index] = mintResult{share: expandShare{ID: share.ConnectID, Code: share.ConnectCode}}
		}()
	}
	wg.Wait()

	shares := make([]expandShare, 0, extra)
	for index, result := range results {
		if result.err != nil {
			logging.Warnf("[expand] expand-%d could not be created: %v", index+1, result.err)
			continue
		}
		shares = append(shares, result.share)
	}
	if len(shares) == 0 {
		return nil, fmt.Errorf("no additional room could be created")
	}
	return shares, nil
}

// expandControllerPool negotiates extra rooms with the served side and joins
// them, widening the pool to target sessions. It runs on the adaptive pool's
// expansion callback, off the connection path, so a failure only leaves the
// tunnel on its single session.
func expandControllerPool(client *api.Client, cfg *auth.Config, negotiator *expandNegotiator, p *peer.Peer, tun *tunnel.Tunnel, pool *tunnel.AdaptiveSessionPool, set *sessionSet, target int, transportMode peer.TransportMode, secPolicy tunnel.SecurityPolicy) error {
	extra := target - pool.Pool().SessionCount()
	if extra <= 0 {
		return nil
	}
	if cfg.JWT == "" {
		// A guest identity cannot join a share at all, so widening the pool
		// would only produce a series of 1002 failures.
		logging.Infof("[expand] staying on a single session: pool expansion needs a logged-in account")
		return nil
	}

	// The mode callback fires while ICE is still selecting a pair, so the
	// control channel usually is not up yet.
	select {
	case <-p.TextChannelOpen():
	case <-time.After(expandChannelTimeout):
		return fmt.Errorf("control channel did not open within %s", expandChannelTimeout)
	}

	logging.Infof("[expand] relay detected; asking the served side for %d more session(s)", extra)
	shares, err := negotiator.request(p, extra)
	if err != nil {
		return err
	}

	// Joining is another round of room joins and WebRTC handshakes, so the
	// offered rooms are taken in parallel as well.
	errs := make([]error, len(shares))
	var wg sync.WaitGroup
	for index, share := range shares {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sessionID := fmt.Sprintf("expand-%d", index+1)
			rt, err := startPooledController(client, cfg, tun, pool, set, sessionID,
				shareEntry(share), false, transportMode, nil, secPolicy)
			if err != nil {
				errs[index] = err
				return
			}
			set.add(rt)
		}()
	}
	wg.Wait()

	joined := 0
	for index, err := range errs {
		if err != nil {
			logging.Warnf("[expand] expand-%d could not join room %s: %v", index+1, shares[index].ID, err)
			continue
		}
		joined++
	}
	if joined == 0 {
		return fmt.Errorf("none of the %d offered rooms could be joined", len(shares))
	}
	logging.Infof("[expand] pool widened to %d session(s)", pool.Pool().SessionCount())
	return nil
}
