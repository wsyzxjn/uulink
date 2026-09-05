package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/wsyzxjn/uulink/pkg/api"
	"github.com/wsyzxjn/uulink/pkg/auth"
	"github.com/wsyzxjn/uulink/pkg/logging"
	"github.com/wsyzxjn/uulink/pkg/peer"
	"github.com/wsyzxjn/uulink/pkg/signaling"
	"github.com/wsyzxjn/uulink/pkg/tunnel"
)

// Multi-session relay pooling: a single TURN allocation is rate limited, so a
// pooled deployment runs one controlled guest room per session and the
// controller joins every share. Streams are pinned to one session each and
// the tunnel state is shared, so ordering within a stream is preserved.

const (
	defaultRelaySessions = 4
	maxRelaySessions     = 16
)

// determineTargetSessions resolves the pool size from the CLI flag, then the
// config file, then the relay default. A value of 1 disables pooling.
func determineTargetSessions(flagValue, configValue int) int {
	if flagValue > 0 {
		return flagValue
	}
	if configValue > 0 {
		return configValue
	}
	return defaultRelaySessions
}

type shareEntry struct {
	ID   string
	Code string
}

// multiSessionShares returns more than one share only when the controller was
// given several shares: comma-separated -share-id/-share-code values or a
// multi-share room file written by the pooled guest server.
func multiSessionShares(roomFile string, shareJoin, shareGuest bool, shareID, shareCode string) ([]shareEntry, error) {
	if roomFile != "" && (shareJoin || shareGuest) {
		shares, err := loadGuestShareFile(roomFile)
		if err != nil {
			return nil, fmt.Errorf("load guest share file: %w", err)
		}
		entries := make([]shareEntry, 0, len(shares))
		for _, share := range shares {
			entries = append(entries, shareEntry{ID: share.ConnectID, Code: share.ConnectCode})
		}
		return entries, nil
	}
	if !strings.Contains(shareID, ",") {
		return nil, nil
	}
	ids := strings.Split(shareID, ",")
	codes := strings.Split(shareCode, ",")
	if len(ids) != len(codes) {
		return nil, fmt.Errorf("mismatched number of share IDs (%d) and share codes (%d)", len(ids), len(codes))
	}
	entries := make([]shareEntry, 0, len(ids))
	for i := range ids {
		id := strings.TrimSpace(ids[i])
		code := strings.TrimSpace(codes[i])
		if id == "" || code == "" {
			return nil, fmt.Errorf("share entry %d has an empty ID or code", i+1)
		}
		entries = append(entries, shareEntry{ID: id, Code: code})
	}
	return entries, nil
}

type multiSessionControllerOptions struct {
	transportMode peer.TransportMode
	useGuest      bool
	shareIDs      string
	shareCodes    string
}

// sessionRuntime owns the signaling connection and peer of one pooled session.
type sessionRuntime struct {
	id      string
	sig     *signaling.Client
	peer    *peer.Peer
	once    sync.Once
	mu      sync.Mutex
	closed  bool
	done    chan struct{}
	cleanup func()
}

func (s *sessionRuntime) close() {
	s.once.Do(func() {
		s.mu.Lock()
		s.closed = true
		if s.cleanup != nil {
			s.cleanup()
		}
		s.mu.Unlock()
		if s.peer != nil {
			_ = s.peer.Close()
		}
		if s.sig != nil {
			_ = s.sig.Close()
		}
		if s.done != nil {
			close(s.done)
		}
	})
}

// activate serializes readiness callbacks with teardown.
func (s *sessionRuntime) activate(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		fn()
	}
}

// sessionSet tracks pooled sessions so they can be closed together and so the
// first failure can stop the whole process.
type sessionSet struct {
	mu       sync.Mutex
	sessions []*sessionRuntime
	failed   chan error
	ready    chan struct{}
	once     sync.Once
	closed   bool
	ctx      context.Context
	cancel   context.CancelFunc
	jobs     sync.WaitGroup
}

func newSessionSet() *sessionSet {
	ctx, cancel := context.WithCancel(context.Background())
	return &sessionSet{failed: make(chan error, 1), ready: make(chan struct{}), ctx: ctx, cancel: cancel}
}

func (s *sessionSet) begin() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.jobs.Add(1)
	return true
}

func (s *sessionSet) add(rt *sessionRuntime) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		rt.close()
		return
	}
	select {
	case <-rt.done:
		s.mu.Unlock()
		return
	default:
	}
	s.sessions = append(s.sessions, rt)
	s.mu.Unlock()
}

func (s *sessionSet) remove(id string) {
	s.mu.Lock()
	var removed *sessionRuntime
	kept := s.sessions[:0]
	for _, rt := range s.sessions {
		if rt.id == id {
			removed = rt
		} else {
			kept = append(kept, rt)
		}
	}
	s.sessions = kept
	s.mu.Unlock()
	if removed != nil {
		removed.close()
	}
}

func (s *sessionSet) fail(err error) {
	select {
	case s.failed <- err:
	default:
	}
}

func (s *sessionSet) closeAll() {
	s.mu.Lock()
	sessions := append([]*sessionRuntime(nil), s.sessions...)
	s.sessions = nil
	s.closed = true
	s.cancel()
	s.mu.Unlock()
	for _, rt := range sessions {
		rt.close()
	}
	s.jobs.Wait()
}

// watchSignaling turns an unexpected signaling disconnect into a pool failure.
func (s *sessionSet) watchSignaling(id string, sig *signaling.Client, done <-chan struct{}) {
	go func() {
		select {
		case <-sig.Done():
			s.fail(fmt.Errorf("%s: %w", id, errSignalingClosed))
		case <-done:
		}
	}()
}

// startTunnelOnce starts the shared tunnel when the first session is ready.
func (s *sessionSet) startTunnelOnce(tun *tunnel.Tunnel, rules []tunnel.Rule, policy tunnel.SecurityPolicy, label string) {
	s.once.Do(func() {
		if len(rules) > 0 {
			if err := tun.Start(); err != nil {
				s.fail(fmt.Errorf("start tunnel: %w", err))
				return
			}
			logActiveMappings(label, rules)
		} else {
			logging.Infof("inbound port mapping active (no local listeners configured)")
		}
		logSecurityPolicy(policy)
		close(s.ready)
	})
}

// waitForShutdown blocks until an interrupt, a session failure, or (when relay
// is required) a readiness timeout.
func (s *sessionSet) waitForShutdown(requireReady bool) error {
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(interrupt)

	if requireReady {
		select {
		case <-s.ready:
			logging.Infof("transport relay ready")
		case <-time.After(relayTransportTimeout):
			return fmt.Errorf("transport relay required: connection not ready within %s", relayTransportTimeout)
		case <-interrupt:
			logging.Infof("interrupted, shutting down")
			return nil
		case err := <-s.failed:
			return err
		}
	}
	select {
	case <-interrupt:
		logging.Infof("interrupted, shutting down")
		return nil
	case err := <-s.failed:
		return err
	}
}

func connectSignaling(room *api.RoomConnectionInfo, controlling bool) (*signaling.Client, error) {
	gateway := room.SignalingServer
	if gateway == "" && len(room.SignalingList) > 0 {
		gateway = room.SignalingList[0]
	}
	sig, err := signaling.Connect(&signaling.ConnectConfig{
		GatewayURL:  gateway,
		NRDAuth:     room.Token,
		Controlling: controlling,
	})
	if err != nil {
		return nil, fmt.Errorf("signaling connect: %w", err)
	}
	select {
	case <-sig.NamespaceConnected():
	case <-time.After(5 * time.Second):
		sig.Close()
		return nil, fmt.Errorf("signaling namespace connect timeout")
	case <-sig.Done():
		return nil, fmt.Errorf("signaling closed before namespace connection")
	}
	return sig, nil
}

// doMultiSessionController joins one share per pooled session and forwards the
// configured rules across all of them.
func doMultiSessionController(client *api.Client, cfg *auth.Config, rules []tunnel.Rule, shares []shareEntry, options multiSessionControllerOptions, secPolicy tunnel.SecurityPolicy) error {
	logging.Infof("starting multi-session controller with %d sessions", len(shares))
	pool := tunnel.NewAdaptiveSessionPool(len(shares), tunnel.PolicyStreamLeastLoaded, nil)
	defer pool.Close()
	tun := tunnel.NewTunnelWithRules(rules, pool)
	tun.SetSecurityPolicy(secPolicy)
	defer tun.Stop()

	set := newSessionSet()
	defer set.closeAll()
	done := make(chan struct{})
	defer close(done)

	// Every session requires relay when the controller asked for it; the
	// server side cannot request relay for a pooled guest room.
	useGuest := options.useGuest || cfg.JWT == ""
	for index, entry := range shares {
		sessionID := fmt.Sprintf("session-%d", index+1)
		rt, err := startPooledController(client, cfg, tun, pool, set, sessionID, entry, useGuest, options.transportMode, rules, secPolicy)
		if err != nil {
			return fmt.Errorf("%s: %w", sessionID, err)
		}
		set.add(rt)
		set.watchSignaling(sessionID, rt.sig, done)
	}

	logging.Infof("waiting for WebRTC connections")
	return set.waitForShutdown(options.transportMode == peer.TransportRelay)
}

func startPooledController(client *api.Client, cfg *auth.Config, tun *tunnel.Tunnel, pool *tunnel.AdaptiveSessionPool, set *sessionSet, sessionID string, entry shareEntry, useGuest bool, transportMode peer.TransportMode, rules []tunnel.Rule, secPolicy tunnel.SecurityPolicy) (*sessionRuntime, error) {
	var room *api.RoomConnectionInfo
	peerDeviceID := cfg.DeviceID
	if useGuest {
		guestSession, _, err := client.CreateUnboundGuest(fmt.Sprintf("guest-ctrl-%s", sessionID))
		if err != nil {
			return nil, fmt.Errorf("create guest: %w", err)
		}
		// A guest controller has its own ephemeral device identity.
		peerDeviceID = guestSession.DeviceID
		room, err = client.JoinRoomByShareCodeWithGuest(guestSession, entry.ID, entry.Code)
		if err != nil {
			return nil, fmt.Errorf("join guest share room: %w", err)
		}
	} else {
		var err error
		room, err = client.JoinRoomByShareCode(entry.ID, entry.Code)
		if err != nil {
			return nil, fmt.Errorf("join share room: %w", err)
		}
	}

	sig, err := connectSignaling(room, true)
	if err != nil {
		return nil, err
	}
	rt := &sessionRuntime{id: sessionID, sig: sig, done: make(chan struct{})}
	// Cleanup is installed before readiness can race with a timeout.
	rt.cleanup = func() { tun.CloseStreams(pool.Pool().RemoveSession(sessionID)) }

	p, err := peer.NewController(&peer.Config{
		Signal:        sig,
		DeviceID:      peerDeviceID,
		TransportMode: transportMode,
		OnSignalData:  tun.HandleMessage,
	})
	if err != nil {
		rt.close()
		return nil, fmt.Errorf("control handshake: %w", err)
	}
	rt.peer = p
	if err := p.Connect(nil); err != nil {
		rt.close()
		return nil, fmt.Errorf("peer connect: %w", err)
	}

	ready := make(chan error, 1)
	p.OnFileChannelOpen(func() {
		if err := p.ValidateTransportMode(); err != nil {
			select {
			case ready <- fmt.Errorf("%s: validate transport: %w", sessionID, err):
			default:
			}
			return
		}
		rt.activate(func() { pool.Pool().AddSession(tunnel.NewSimpleSession(sessionID, &peerSender{peer: p}, nil)) })
		select {
		case ready <- nil:
		default:
		}
		logging.Infof("[pool] controller %s ready (sessions in pool: %d)", sessionID, pool.Pool().SessionCount())
		set.startTunnelOnce(tun, rules, secPolicy, "multi-session port forwarding active")
	})
	select {
	case err := <-ready:
		if err == nil {
			monitorSession(set, rt, tun, pool.Pool())
			return rt, nil
		}
		rt.close()
		return nil, err
	case <-set.ctx.Done():
		rt.close()
		return nil, set.ctx.Err()
	case <-sig.Done():
		rt.close()
		return nil, fmt.Errorf("%s: signaling closed before data channel ready", sessionID)
	case <-time.After(relayTransportTimeout):
		rt.close()
		return nil, fmt.Errorf("%s: data channel readiness timeout", sessionID)
	}
}

// doMultiSessionUnboundGuestServe creates one unbound guest room per session
// and serves the configured rules through the pooled sessions.
func doMultiSessionUnboundGuestServe(cfg *auth.Config, rules []tunnel.Rule, roomFile string, shareOptions guestShareOptions, policy tunnel.SecurityPolicy, targetSessions int) error {
	hostname, err := cfg.EffectiveHostname()
	if err != nil {
		return fmt.Errorf("resolve hostname: %w", err)
	}
	logging.Infof("initializing %d unbound guest sessions for the relay pool", targetSessions)

	pool := tunnel.NewAdaptiveSessionPool(targetSessions, tunnel.PolicyStreamLeastLoaded, nil)
	defer pool.Close()
	tun := tunnel.NewTunnelWithRules(rules, pool)
	tun.SetSecurityPolicy(policy)
	defer tun.Stop()

	set := newSessionSet()
	defer set.closeAll()
	done := make(chan struct{})
	defer close(done)

	shares := make([]*api.GuestShareInfo, 0, targetSessions)
	for index := range targetSessions {
		sessionID := fmt.Sprintf("session-%d", index+1)
		sessionCfg := *cfg
		if index > 0 {
			sessionCfg.UnboundClientID = ""
			sessionCfg.UnboundDeviceID = ""
		}
		rt, share, err := startPooledGuestServer(api.NewClient(&sessionCfg), tun, pool, set, sessionID, fmt.Sprintf("%s-%d", hostname, index+1), shareOptions, rules, policy)
		if err != nil {
			return fmt.Errorf("%s: %w", sessionID, err)
		}
		set.add(rt)
		set.watchSignaling(sessionID, rt.sig, done)
		shares = append(shares, share)
	}

	if roomFile != "" {
		if err := saveMultiGuestShareFile(roomFile, shares); err != nil {
			return fmt.Errorf("save multi guest share file: %w", err)
		}
		logging.Debugf("saved %d guest shares to %s", len(shares), roomFile)
	}
	ids := make([]string, 0, len(shares))
	codes := make([]string, 0, len(shares))
	for _, share := range shares {
		ids = append(ids, share.ConnectID)
		codes = append(codes, share.ConnectCode)
	}
	logging.Infof("multi-session guest shares ready (%d sessions): -share-id %s -share-code %s",
		len(shares), strings.Join(ids, ","), strings.Join(codes, ","))

	return set.waitForShutdown(false)
}

func startPooledGuestServer(client *api.Client, tun *tunnel.Tunnel, pool *tunnel.AdaptiveSessionPool, set *sessionSet, sessionID, hostname string, shareOptions guestShareOptions, rules []tunnel.Rule, policy tunnel.SecurityPolicy) (*sessionRuntime, *api.GuestShareInfo, error) {
	guestSession, _, err := client.CreateUnboundGuest(hostname)
	if err != nil {
		return nil, nil, fmt.Errorf("create unbound guest: %w", err)
	}
	// The guest session carries its own client/device identity, so the shared
	// client signs every request for this session with the right headers.
	room, err := client.CreateGuestRoom(guestSession)
	if err != nil {
		return nil, nil, fmt.Errorf("create guest room: %w", err)
	}

	sig, err := connectSignaling(room, false)
	if err != nil {
		return nil, nil, err
	}
	rt := &sessionRuntime{id: sessionID, sig: sig, done: make(chan struct{})}
	rt.cleanup = func() { tun.CloseStreams(pool.Pool().RemoveSession(sessionID)) }

	if _, err := client.GuestSetDeviceControllable(guestSession, true); err != nil {
		rt.close()
		return nil, nil, fmt.Errorf("set guest device controllable: %w", err)
	}
	share, err := waitForGuestConnectID(client, guestSession)
	if err != nil {
		rt.close()
		return nil, nil, fmt.Errorf("get guest share info: %w", err)
	}
	share, err = ensureGuestShareCode(client, guestSession, share, shareOptions)
	if err != nil {
		rt.close()
		return nil, nil, fmt.Errorf("prepare guest share code: %w", err)
	}
	controlModeID := shareOptions.ControlID
	if controlModeID == "" {
		controlModeID = share.ConnectID
	}
	if _, err := client.GuestShareUploadControlMode(guestSession,
		api.NewGuestShareUploadControlModeRequest(controlModeID, true, shareOptions.AuthMode)); err != nil {
		rt.close()
		return nil, nil, fmt.Errorf("upload guest control mode: %w", err)
	}

	var shareMu sync.Mutex
	currentShare := share
	sig.On("bmsg_push", func(ev *signaling.Event) {
		if len(ev.Args) == 0 {
			return
		}
		var push struct {
			Type string `json:"type"`
			Data struct {
				ControlID string `json:"control_id"`
				Salt      string `json:"salt"`
			} `json:"data"`
		}
		if err := json.Unmarshal(ev.Args[0], &push); err != nil {
			logging.Errorf("[%s] controlled bmsg_push parse error: %v", sessionID, err)
			return
		}
		if push.Data.ControlID == "" {
			logging.Debugf("[%s] controlled bmsg_push type=%q without control_id", sessionID, push.Type)
			return
		}
		shareMu.Lock()
		defer shareMu.Unlock()
		switch push.Type {
		case "remote_control":
			updatedShare, err := uploadGuestShareCode(client, guestSession, currentShare, push.Data.ControlID, push.Data.Salt, shareOptions)
			if err != nil {
				logging.Errorf("[%s] upload remote-control guest share sign failed: %v", sessionID, err)
				return
			}
			currentShare = updatedShare
			if _, err := client.GuestShareConfirmation(guestSession, &api.GuestShareConfirmationRequest{
				ControlID:    push.Data.ControlID,
				AllowControl: true,
				NeedPassword: shareOptions.AuthMode != api.ShareAuthCustom,
			}); err != nil {
				logging.Errorf("[%s] confirm remote control failed: %v", sessionID, err)
				return
			}
			logging.Infof("[%s] remote control confirmed", sessionID)
		case "get_control_mode":
			updatedShare, err := uploadGuestShareCode(client, guestSession, currentShare, push.Data.ControlID, push.Data.Salt, shareOptions)
			if err != nil {
				logging.Errorf("[%s] upload pushed guest share sign failed: %v", sessionID, err)
				return
			}
			currentShare = updatedShare
			if _, err := client.GuestShareUploadControlMode(guestSession,
				api.NewGuestShareUploadControlModeRequest(push.Data.ControlID, true, shareOptions.AuthMode)); err != nil {
				logging.Errorf("[%s] upload pushed control mode failed: %v", sessionID, err)
			}
		default:
			logging.Debugf("[%s] controlled bmsg_push type=%q", sessionID, push.Type)
		}
	})

	var poolSession *tunnel.SimpleSession
	wired := make(chan struct{})
	p, err := peer.NewControlled(&peer.Config{
		Signal: sig,
		OnSignalData: func(data []byte) {
			<-wired
			// Replies for a stream must leave through the session its CONNECT
			// arrived on; bind the stream before the tunnel handles the frame.
			if frame := tunnel.DecodeFrameForTunnel(data); frame != nil {
				pool.Pool().BindStream(frame.RuleID, frame.StreamID, poolSession)
			}
			tun.HandleMessage(data)
		},
	})
	if err != nil {
		rt.close()
		return nil, nil, fmt.Errorf("create controlled peer: %w", err)
	}
	rt.peer = p
	poolSession = tunnel.NewSimpleSession(sessionID, &peerSender{peer: p}, nil)
	close(wired)
	p.OnFileChannelOpen(func() {
		rt.activate(func() { pool.Pool().AddSession(poolSession) })
		logging.Infof("[pool] controlled %s ready (sessions in pool: %d)", sessionID, pool.Pool().SessionCount())
		set.startTunnelOnce(tun, rules, policy, "multi-session reverse port forwarding active")
	})

	if room.ReportURL != "" && room.ReportToken != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := client.ReportIPContext(ctx, room); err != nil {
			logging.Debugf("[%s] report relay IP: %v", sessionID, err)
		}
		if _, err := client.ReportEchoServersContext(ctx, room); err != nil {
			logging.Debugf("[%s] report relay echo servers: %v", sessionID, err)
		}
	}
	monitorSession(set, rt, tun, pool.Pool())
	return rt, share, nil
}

func saveMultiGuestShareFile(path string, shares []*api.GuestShareInfo) error {
	infos := make([]guestShareFileInfo, len(shares))
	for i, share := range shares {
		infos[i] = guestShareFileInfo{
			ConnectID:     share.ConnectID,
			ConnectCode:   share.ConnectCode,
			TemporaryCode: share.TemporaryCode,
			CustomCode:    share.CustomCode,
			ControlID:     share.ControlID,
		}
	}
	data, err := json.MarshalIndent(infos, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// loadGuestShareFile reads either the multi-share array written by the pooled
// guest server or the single object written by serveRoom.
func loadGuestShareFile(path string) ([]*api.GuestShareInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var infos []guestShareFileInfo
	if err := json.Unmarshal(data, &infos); err != nil {
		var single guestShareFileInfo
		if err := json.Unmarshal(data, &single); err != nil {
			return nil, fmt.Errorf("parse guest share file %s: %w", path, err)
		}
		infos = []guestShareFileInfo{single}
	}
	shares := make([]*api.GuestShareInfo, 0, len(infos))
	for _, info := range infos {
		if info.ConnectID == "" {
			return nil, errors.New("guest share file entry has no connect_id")
		}
		shares = append(shares, &api.GuestShareInfo{
			ConnectID:     info.ConnectID,
			ConnectCode:   info.ConnectCode,
			TemporaryCode: info.TemporaryCode,
			CustomCode:    info.CustomCode,
			ControlID:     info.ControlID,
		})
	}
	return shares, nil
}
