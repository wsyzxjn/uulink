package main

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/wsyzxjn/uulink/pkg/api"
	"github.com/wsyzxjn/uulink/pkg/auth"
	"github.com/wsyzxjn/uulink/pkg/landiscover"
	"github.com/wsyzxjn/uulink/pkg/logging"
	"github.com/wsyzxjn/uulink/pkg/peer"
	"github.com/wsyzxjn/uulink/pkg/proto/gvpb"
	"github.com/wsyzxjn/uulink/pkg/signaling"
	"github.com/wsyzxjn/uulink/pkg/tunnel"
)

type controllerOptions struct {
	// deviceID is the target device for a same-account join. It is already
	// resolved against the config and validated by the caller.
	deviceID          string
	controlDeviceID   string
	roomFile          string
	shareJoin         bool
	shareConfirmation bool
	shareControlID    string
	shareGuest        bool
	shareID           string
	shareCode         string
	capability        string
	transportMode     peer.TransportMode
	pckSweep          bool
	mixKCP            bool
	targetSessions    int
	autoSessions      bool
	// rules are the local listeners; the caller has validated them.
	rules []tunnel.Rule
	// lanDiscovery announces the first forwarded port as a Minecraft LAN
	// server once the tunnel is up.
	lanDiscovery bool
	lanMotd      string
	configPath   string
	p2pTimeout   time.Duration
}

const (
	defaultP2PTimeout     = 12 * time.Second
	relayTransportTimeout = 30 * time.Second
)

var (
	errP2PTimeout      = errors.New("p2p connection timeout")
	errSignalingClosed = errors.New("signaling connection closed unexpectedly")
)

func runController(ctx context.Context, client *api.Client, cfg *auth.Config, secPolicy tunnel.SecurityPolicy, options controllerOptions) error {
	targetDevID := options.deviceID
	rules := options.rules
	var err error

	// Step 1: join the room created by the target device's server
	var room *api.RoomConnectionInfo
	controllerAppControlID := ""
	controllerGuestDeviceID := ""
	if options.shareJoin || options.shareConfirmation {
		logging.Infof("joining share room as controller")
	}
	switch {
	case options.shareConfirmation:
		if options.shareControlID == "" {
			_, controlModeErr := client.GetShareControlMode(options.shareID)
			if controlModeErr != nil {
				logging.Debugf("share control mode query failed: %v", controlModeErr)
			}
		}
		controlID := options.shareControlID
		if options.shareControlID != "" {
			logging.Debugf("using explicit share control_id=%s", controlID)
		} else {
			var err error
			controlID, err = generateAppControlID()
			if err != nil {
				return fmt.Errorf("generate share control id: %w", err)
			}
			logging.Debugf("generated share control_id_length=%d", len(controlID))
		}
		controllerAppControlID = controlID
		room, err = client.JoinRoomByConfirmation(options.shareID, controlID)
		if err != nil {
			var responseErr *api.ResponseError
			if errors.As(err, &responseErr) {
				data, _ := responseErr.Response["data"].(map[string]any)
				logging.Debugf("join room by confirmation error data keys=%v", mapKeys(data))
			}
			return fmt.Errorf("join room by confirmation: %w", err)
		}
	case options.shareJoin:
		room, err = client.JoinRoomByShareCode(options.shareID, options.shareCode)
		if err != nil {
			var responseErr *api.ResponseError
			if errors.As(err, &responseErr) {
				data, _ := responseErr.Response["data"].(map[string]any)
				logging.Debugf("join room by share code error data keys=%v", mapKeys(data))
			}
			return fmt.Errorf("join share room: %w", err)
		}
	case options.shareGuest:
		var guestSession *api.GuestSession
		var guestErr error
		if cfg.DeviceID != "" && cfg.ClientID != "" && (cfg.Platform == 1 || runtime.GOOS == "windows") {
			guestSession, guestErr = client.CreateGuest()
		}
		if guestSession == nil {
			var identity *api.UnboundDeviceIdentity
			guestSession, identity, guestErr = client.CreateUnboundGuest("guest-controller")
			if guestErr == nil && identity != nil {
				cfg.ClientID = identity.ClientID
				cfg.DeviceID = identity.DeviceID
				cfg.Platform = 1
				if options.configPath != "" {
					_ = auth.SaveConfigFile(options.configPath, cfg)
				}
			}
		}
		if guestErr != nil {
			return fmt.Errorf("create guest: %w", guestErr)
		}
		controllerGuestDeviceID = guestSession.DeviceID
		room, err = client.JoinRoomByShareCodeWithGuest(guestSession, options.shareID, options.shareCode)
		if err != nil {
			var responseErr *api.ResponseError
			if errors.As(err, &responseErr) && responseErr.Code == api.CodeObjectNotFound {
				// A server-side restriction, not a transient condition.
				return permanent(fmt.Errorf("join guest share room: %w; the API only exposes "+
					"shares to logged-in users, so the controlling side cannot join "+
					"with a guest identity: run %q on this machine and retry, the "+
					"served side can stay accountless", err, "uulink -login"))
			}
			return fmt.Errorf("join guest share room: %w", err)
		}
	case options.roomFile != "":
		room, err = loadRoomFile(options.roomFile)
		if err != nil {
			return fmt.Errorf("load room file: %w", err)
		}
		logging.Debugf("loaded room from %s", options.roomFile)
		// The room-file controller reuses the guest's signaling token. The
		// passive peer skips the controller-role events that the gateway
		// rejects for this token, while Controlling=true prevents the gateway
		// from treating the second connection as a duplicate controlled session.
		room.IsRoomFileController = true
	default:
		logging.Infof("joining remote device %s", targetDevID)
		room, err = client.JoinRoomByDevice(targetDevID, false)
		if err != nil {
			return fmt.Errorf("join room: %w", err)
		}
	}
	logging.Debugf("signaling server=%s gateways=%d", room.SignalingServer, len(room.SignalingList))
	if err := ctx.Err(); err != nil {
		return nil
	}

	// Step 2: connect to signaling gateway, falling back through the
	// candidates the room advertised.
	sig, err := connectSignaling(room, true)
	if err != nil {
		return fmt.Errorf("signaling connect: %w", err)
	}
	defer sig.Close()
	if err := ctx.Err(); err != nil {
		return nil
	}

	// Log forward_setting events (server pushes these after answer)
	sig.On("forward_setting", func(ev *signaling.Event) {
		if len(ev.Args) > 0 {
			logging.Debugf("[signaling] forward_setting received (%d bytes)", len(ev.Args[0]))
		}
	})

	if options.capability != "" {
		if err := peer.CapOverride(options.capability); err != nil {
			return permanent(fmt.Errorf("cap override: %w", err))
		}
		logging.Debugf("capability blob overridden: %s", options.capability)
	}
	var debugRule tunnel.Rule
	var ruleID string
	if len(rules) > 0 {
		debugRule = rules[0]
		ruleID = debugRule.ID
	}
	if (options.pckSweep || options.mixKCP) && len(rules) == 0 {
		return permanent(fmt.Errorf("-pck-sweep and -mixkcp require at least one port mapping"))
	}

	// Step 4: control handshake (gets client_id, ice_id, TURN servers)
	var tun *tunnel.Tunnel
	peerDeviceID := cfg.DeviceID
	if options.controlDeviceID != "" {
		peerDeviceID = options.controlDeviceID
		logging.Debugf("control ConnectOptions device_id=%s auth_device_id=%s", peerDeviceID, cfg.DeviceID)
	} else if controllerGuestDeviceID != "" {
		// A guest controller has its own ephemeral device identity. Keep it
		// separate from the logged-in config device used for API headers.
		peerDeviceID = controllerGuestDeviceID
		logging.Debugf("control ConnectOptions device_id=%s auth_device_id=%s", peerDeviceID, cfg.DeviceID)
	}
	wired := make(chan struct{})
	var primarySession tunnel.Session
	var expandPool *tunnel.AdaptiveSessionPool
	p, err := peer.NewController(&peer.Config{
		Signal:        sig,
		DeviceID:      peerDeviceID,
		AppControlID:  controllerAppControlID,
		Passive:       room.IsRoomFileController,
		TransportMode: options.transportMode,
		OnSignalData: func(data []byte) {
			<-wired
			frame := tunnel.DecodeFrameForTunnel(data)
			if frame == nil {
				return
			}
			expandPool.Pool().ObserveReceived("primary", len(data))
			// Replies for a peer-initiated stream must leave through the
			// session its CONNECT arrived on. Only a CONNECT creates a
			// binding; the tunnel releases it when the stream is done.
			if frame.Type == gvpb.TypeConnect {
				expandPool.Pool().BindStream(frame.RuleID, frame.StreamID, primarySession)
			}
			tun.HandleFrame(frame)
		}})
	if err != nil {
		return fmt.Errorf("control handshake: %w", err)
	}
	defer p.Close()

	// Step 6: start the local listener once the PM data channel is ready.
	// A relayed session is rate limited per TURN allocation, so the pool asks
	// the served side for additional rooms in band and joins them here. The
	// negotiator has to be in place before the peer reports its mode.
	negotiator := newExpandNegotiator()
	expandSet := newSessionSet()
	defer expandSet.closeAll()
	recoveryConfig := *cfg
	adaptivePool := tunnel.NewAdaptiveSessionPool(options.targetSessions, tunnel.PolicyHealthAware,
		func(target int) error {
			batch := target - 1
			if options.autoSessions {
				batch = 1
			}
			return maintainControllerPool(client, &recoveryConfig, negotiator, p, tun, expandPool, expandSet, target, batch, options.transportMode, options.p2pTimeout, secPolicy)
		})
	expandPool = adaptivePool
	primarySession = tunnel.NewSimpleSession("primary", &peerSender{peer: p}, nil)
	adaptivePool.Pool().AddSession(primarySession)
	p.OnTextMessage(func(data []byte) { negotiator.handle(data) })
	p.OnModeChange(adaptivePool.OnModeDetected)

	tun = tunnel.NewTunnelWithRules(rules, adaptivePool)
	tun.SetSecurityPolicy(secPolicy)
	close(wired)
	runErr := make(chan error, 1)
	monitorPrimary(expandSet.ctx, p, runErr)
	tunnelReady := make(chan struct{})
	var tunnelReadyOnce sync.Once
	// The LAN announcer is started from the data-channel callback and stopped
	// from this goroutine, so guard it.
	var lanMu sync.Mutex
	var lanAnnouncer *landiscover.Service
	p.OnFileChannelOpen(func() {
		if err := p.ValidateTransportMode(); err != nil {
			select {
			case runErr <- fmt.Errorf("validate transport: %w", err):
			default:
			}
			return
		}
		if len(rules) > 0 {
			if err := tun.Start(); err != nil {
				select {
				case runErr <- fmt.Errorf("start tunnel: %w", err):
				default:
				}
				return
			}
			logActiveMappings("port forwarding active", rules)
			if options.lanDiscovery {
				lanMu.Lock()
				if lanAnnouncer == nil {
					announcer, err := landiscover.Start(options.lanMotd, rules[0].LocalPort, 0)
					if err != nil {
						logging.Warnf("start LAN discovery: %v", err)
					}
					lanAnnouncer = announcer
				}
				lanMu.Unlock()
			}
		} else {
			logging.Infof("inbound port mapping active (no local listeners configured)")
		}
		logSecurityPolicy(secPolicy)
		tunnelReadyOnce.Do(func() { close(tunnelReady) })
	})
	defer tun.Stop()
	defer func() {
		lanMu.Lock()
		announcer := lanAnnouncer
		lanMu.Unlock()
		if announcer != nil {
			announcer.Stop()
		}
	}()

	if err := p.Connect(nil); err != nil {
		return fmt.Errorf("peer connect: %w", err)
	}

	if options.pckSweep {
		startPCKSweep(p, debugRule, ruleID)
	}

	logging.Infof("waiting for WebRTC connection")

	if options.mixKCP {
		startMixKCPProbe(p, debugRule, ruleID)
	}

	sig.On("bmsg_push", func(ev *signaling.Event) {
		if len(ev.Args) > 0 {
			logging.Debugf("[signaling] bmsg_push received (%d bytes)", len(ev.Args[0]))
		}
	})
	sig.On("peerConnected", func(ev *signaling.Event) {
		logging.Infof("peer connected")
	})
	sig.On("peerError", func(ev *signaling.Event) {
		if len(ev.Args) > 0 {
			logging.Errorf("peer error: %s", truncate(string(ev.Args[0]), 150))
		}
	})

	// A P2P attempt in auto mode is abandoned after p2pTimeout so the next
	// attempt can require a relay; zero disables that fallback.
	var p2pTimer <-chan time.Time
	if options.transportMode == peer.TransportAuto && options.p2pTimeout > 0 {
		p2pTimer = time.After(options.p2pTimeout)
	}
	readyTimeout := time.After(relayTransportTimeout)

	select {
	case <-tunnelReady:
		logging.Infof("transport connection ready (mode=%s)", p.SelectedPairMode())
	case <-p2pTimer:
		state := p.ConnectionState()
		logging.Infof("[peer] %s countdown: peer connection state is %s", options.p2pTimeout, state)
		if state != "connected" {
			return fmt.Errorf("%w: peer connection state is %s after %s countdown", errP2PTimeout, state, options.p2pTimeout)
		}
		select {
		case <-tunnelReady:
			logging.Infof("transport connection ready (mode=%s)", p.SelectedPairMode())
		case <-readyTimeout:
			return fmt.Errorf("transport connection timeout: connection not ready within %s", relayTransportTimeout)
		case <-ctx.Done():
			logging.Infof("interrupted, shutting down")
			return nil
		case <-sig.Done():
			return errSignalingClosed
		case err := <-runErr:
			return err
		}
	case <-readyTimeout:
		return fmt.Errorf("transport connection timeout: connection not ready within %s", relayTransportTimeout)
	case <-ctx.Done():
		logging.Infof("interrupted, shutting down")
		return nil
	case <-sig.Done():
		return errSignalingClosed
	case err := <-runErr:
		return err
	}

	select {
	case <-ctx.Done():
		logging.Infof("interrupted, shutting down")
	case <-sig.Done():
		return errSignalingClosed
	case err := <-runErr:
		return err
	}
	return nil
}
