package main

import (
	"context"
	"encoding/json"
	"errors"
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
	RequestID string        `json:"request_id,omitempty"`
	UULink    int           `json:"uulink"`
	Type      string        `json:"type"`
	Sessions  int           `json:"sessions,omitempty"`
	Shares    []expandShare `json:"shares,omitempty"`
	Message   string        `json:"message,omitempty"`
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
	mu        sync.Mutex
	requestMu sync.Mutex
	next      uint64
	active    string
	result    chan *expandMessage
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
		if msg.RequestID != "" && msg.RequestID != n.active {
			return true
		}
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
	return n.requestContext(context.Background(), p, extra)
}

func (n *expandNegotiator) requestContext(ctx context.Context, p textSender, extra int) ([]expandShare, error) {
	n.requestMu.Lock()
	defer n.requestMu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	n.mu.Lock()
	n.next++
	n.active = fmt.Sprint(n.next)
	id := n.active
	n.mu.Unlock()

	if err := sendExpandMessage(p, &expandMessage{Type: expandTypeRequest, Sessions: extra, RequestID: id}); err != nil {
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
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(expandOfferTimeout):
		return nil, fmt.Errorf("peer did not answer the expansion request within %s", expandOfferTimeout)
	}
}

// expandMinter creates the extra rooms on the served side. It returns the
// shares a controller may join, and is expected to be safe to call once.
type expandMinter func(extra int) ([]expandShare, error)

// Requests are replayable. The minter reconciles a bounded set of room slots,
// so repeated requests repair failed rooms instead of leaking guest identities.
func serveExpandRequests(p textSender, maxExtra int, mint expandMinter) func([]byte) {
	var mu sync.Mutex
	var previous *expandMessage
	return func(data []byte) {
		msg, ok := parseExpandMessage(data)
		if !ok || msg.Type != expandTypeRequest {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if previous != nil && previous.RequestID == msg.RequestID {
			_ = sendExpandMessage(p, previous)
			return
		}
		extra := min(msg.Sessions, maxExtra, maxExpandSessions)
		reply := &expandMessage{RequestID: msg.RequestID, Type: expandTypeOffer}
		if extra <= 0 {
			reply.Type = expandTypeError
			reply.Message = "this endpoint is configured for a single session"
		} else {
			logging.Infof("[expand] controller requested %d additional session(s)", extra)
			shares, err := mint(extra)
			if err != nil {
				reply.Type = expandTypeError
				reply.Message = err.Error()
			} else {
				reply.Shares = shares
			}
		}
		previous = reply
		if err := sendExpandMessage(p, reply); err != nil {
			logging.Warnf("[expand] offer failed: %v", err)
		}
	}
}

// Every slot keeps its own guest identity across repair attempts. Healthy rooms
// and their TCP connections remain untouched when another slot is repaired.
func newExpansionMinter(cfg *auth.Config, tun *tunnel.Tunnel, pool *tunnel.AdaptiveSessionPool, set *sessionSet, options guestShareOptions, policy tunnel.SecurityPolicy) expandMinter {
	type slot struct {
		config auth.Config
		rt     *sessionRuntime
		share  expandShare
	}
	slots := make([]slot, maxExpandSessions)
	for i := range slots {
		slots[i].config = *cfg
		slots[i].config.UnboundClientID = ""
		slots[i].config.UnboundDeviceID = ""
		slots[i].config.CustomCode = ""
		slots[i].config.ShareID = ""
	}
	options.ConfigPath = ""
	options.PublishURL = ""
	options.ControlID = ""
	var mu sync.Mutex
	return func(extra int) ([]expandShare, error) {
		if !set.begin() {
			return nil, context.Canceled
		}
		defer set.jobs.Done()
		mu.Lock()
		defer mu.Unlock()
		if err := set.ctx.Err(); err != nil {
			return nil, err
		}
		extra = min(extra, len(slots))
		var wg sync.WaitGroup
		for i := range extra {
			wg.Add(1)
			go func() {
				defer wg.Done()
				slot := &slots[i]
				if slot.rt != nil {
					select {
					case <-slot.rt.done:
						slot.rt = nil
					default:
						return
					}
				}
				copyConfig := slot.config
				rt, share, err := startPooledGuestServer(api.NewClient(&copyConfig), tun, pool, set, nextSessionID(fmt.Sprintf("expand-%d", i+1)), fmt.Sprintf("uulink-expand-%d", i+1), options, nil, policy)
				slot.config = copyConfig
				if err != nil {
					logging.Warnf("[expand] room %d repair failed: %v", i+1, err)
					return
				}
				set.add(rt)
				slot.rt = rt
				slot.share = expandShare{ID: share.ConnectID, Code: share.ConnectCode}
			}()
		}
		wg.Wait()
		if err := set.ctx.Err(); err != nil {
			return nil, err
		}
		var shares []expandShare
		for i := range extra {
			if slots[i].rt != nil {
				select {
				case <-slots[i].rt.done:
				default:
					shares = append(shares, slots[i].share)
				}
			}
		}
		if len(shares) == 0 {
			return nil, fmt.Errorf("no additional room could be created")
		}
		return shares, nil
	}
}

// maintainControllerPool is the sole repair coordinator. It retries partial
// expansion with capped backoff and never rejoins an already healthy room.
func maintainControllerPool(client *api.Client, cfg *auth.Config, n *expandNegotiator, p *peer.Peer, tun *tunnel.Tunnel, pool *tunnel.AdaptiveSessionPool, set *sessionSet, target int, mode peer.TransportMode, policy tunnel.SecurityPolicy) error {
	if !set.begin() {
		return nil
	}
	defer set.jobs.Done()
	if cfg.JWT == "" {
		return nil
	}
	known := make(map[string]*sessionRuntime)
	return reconcileLoop(set.ctx, func(ctx context.Context) error {
		for id, rt := range known {
			select {
			case <-rt.done:
				delete(known, id)
			default:
			}
		}
		if pool.Pool().SessionCount() >= target {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-p.TextChannelOpen():
		case <-time.After(expandChannelTimeout):
			return fmt.Errorf("control channel readiness timeout")
		}
		shares, err := n.requestContext(ctx, p, target-1)
		if err != nil {
			return err
		}
		type joined struct {
			share expandShare
			rt    *sessionRuntime
		}
		results := make([]joined, len(shares))
		var wg sync.WaitGroup
		for i, share := range shares {
			if known[share.ID] != nil {
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				if ctx.Err() != nil {
					return
				}
				rt, err := startPooledController(client, cfg, tun, pool, set, nextSessionID("expand"), shareEntry(share), false, mode, nil, policy)
				if errors.Is(err, errP2PTimeout) && mode == peer.TransportAuto {
					logging.Infof("[expand] P2P timed out, retrying session with relay transport")
					rt, err = startPooledController(client, cfg, tun, pool, set, nextSessionID("expand"), shareEntry(share), false, peer.TransportRelay, nil, policy)
				}
				if err != nil {
					logging.Warnf("[recovery] join extra room failed: %v", err)
					return
				}
				set.add(rt)
				results[i] = joined{share, rt}
			}()
		}
		wg.Wait()
		for _, r := range results {
			if r.rt != nil {
				known[r.share.ID] = r.rt
			}
		}
		count := pool.Pool().SessionCount()
		logging.Infof("[expand] pool ready: %d/%d session(s)", count, target)
		if count < target {
			return fmt.Errorf("pool below target: %d/%d", count, target)
		}
		return nil
	})
}
