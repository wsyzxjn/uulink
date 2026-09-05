// uulink - standalone UU Remote client for port forwarding.
package main

import (
	"bufio"
	crand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/wsyzxjn/uulink/pkg/api"
	"github.com/wsyzxjn/uulink/pkg/auth"
	"github.com/wsyzxjn/uulink/pkg/landiscover"
	"github.com/wsyzxjn/uulink/pkg/logging"
	"github.com/wsyzxjn/uulink/pkg/peer"
	"github.com/wsyzxjn/uulink/pkg/signaling"
	"github.com/wsyzxjn/uulink/pkg/tunnel"
)

// DefaultConfigURL can be baked into a client build so it runs without flags:
// go build -ldflags="-X main.DefaultConfigURL=https://example.com/room.json"
var DefaultConfigURL string

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	configPath := flag.String("config", "config.json", "path to config file")
	deviceID := flag.String("device", "", "device ID to connect to (overrides config)")
	allowSelf := flag.Bool("allow-self", false, "allow controller and server to share one configured device ID (same-host integration test)")
	controlDeviceID := flag.String("control-device-id", "", "device ID sent in the control ConnectOptions attachment (defaults to config device_id)")
	serveMode := flag.Bool("serve", false, "create a room and answer a UULink controller")
	guestServe := flag.Bool("guest-serve", false, "create a guest-controlled room and answer a logged-in UULink controller")
	unboundGuestServe := flag.Bool("unbound-guest-serve", false, "register a new accountless device, then create a guest-controlled room (avoids same-account self-assist blocks)")
	guestControlID := flag.String("guest-control-id", "", "controller control ID used for the guest share verification sign (defaults to connect_id)")
	shareAuthMode := flag.String("share-auth-mode", "temporary", "guest share authorization mode: temporary, custom, or both")
	guestCustomCode := flag.String("guest-custom-code", "", "custom guest share code for custom or both modes (generated when omitted)")
	roomFile := flag.String("room-file", "", "share room connection or guest share info through a file (same-host debug E2E)")
	listDevices := flag.Bool("list", false, "list available devices and exit")
	guestTest := flag.Bool("guest", false, "run guest identity/share smoke test and exit")
	userInfo := flag.Bool("user-info", false, "show current user info and exit")
	interactiveLogin := flag.Bool("login", false, "interactively select login method (QR code or SMS code)")
	loginQRCode := flag.Bool("login-qrcode", false, "exchange an official QR-code login for a JWT and update the config")
	loginMobile := flag.String("login-mobile", "", "mobile phone number for SMS verification code login")
	loginCountryCode := flag.String("login-country-code", "+86", "country code for mobile login (default: +86)")
	refreshLogin := flag.Bool("refresh-login", false, "validate the current JWT and refresh it by QR-code login only if needed")
	loginQRCodeTimeout := flag.Duration("login-qrcode-timeout", 5*time.Minute, "maximum time to wait for QR-code login confirmation")
	shareJoin := flag.Bool("share", false, "join a remote-assistance share by ID and code")
	shareConfirmation := flag.Bool("share-confirmation", false, "join a remote-assistance share by confirmation")
	shareControlMode := flag.Bool("share-control-mode", false, "query a remote-assistance share control mode and exit")
	shareControlID := flag.String("share-control-id", "", "controller control ID for by_confirmation (generated when omitted)")
	shareGuest := flag.Bool("share-guest", false, "join a remote-assistance share using a guest identity")
	shareID := flag.String("share-id", "", "remote-assistance connect ID")
	shareCode := flag.String("share-code", "", "remote-assistance verification code")
	ruleIDFlag := flag.String("rule-id", "", "registered rule ID on the remote device (must match)")
	capFlag := flag.String("cap", "", "override ConnectOptions capability blob (hex, e.g. 08061002180120023002380240024801)")
	transportFlag := flag.String("transport", "auto", "WebRTC transport policy for controller sessions: auto or relay")
	pckSweep := flag.Bool("pck-sweep", false, "sweep PCK.V3 channels with CONNECT frames after setup")
	mixkcpMode := flag.Bool("mixkcp", false, "send PM frames over mix-kcp UDP to the ICE peer (raw frame format, crypto layout preserved)")
	localPort := flag.String("local", "", "local port or port range to listen on (e.g. 8080 or 9000-9010)")
	localHost := flag.String("local-host", "127.0.0.1", "local address to listen on")
	remoteHost := flag.String("remote-host", "127.0.0.1", "remote target host")
	remotePort := flag.String("remote-port", "", "remote target port or port range (e.g. 8080 or 9000-9010)")
	mappingFlag := flag.String("mapping", "", "port forwarding rule or range (e.g. 8080:8080 or 9000-9010:8000-8010)")
	logLevel := flag.String("log-level", "info", "log level: debug, info, warn, or error")
	allowLAN := flag.Bool("allow-lan", false, "allow incoming mappings to target non-loopback LAN/WAN addresses (default: loopback only)")
	allowedPortsFlag := flag.String("allowed-ports", "", "comma-separated list or ranges of allowed target ports (e.g. 22,8080,9000-9010)")
	sessionsFlag := flag.Int("sessions", 0, "relay session pool size (default: 4 when the connection is relayed; 1 disables pooling)")
	customServe := flag.Bool("custom-serve", false, "run an accountless assistance server that accepts a fixed custom verification code")
	customConnect := flag.String("custom-connect", "", "connect ID of a custom-code assistance server to connect to")
	customCodeFlag := flag.String("custom-code", "", "custom verification code (8-16 letters and digits) for -custom-serve or -custom-connect")
	configURL := flag.String("config-url", DefaultConfigURL, "URL or file path of a remote share configuration to connect with")
	publishURL := flag.String("publish-url", "", "webhook URL that receives the share configuration when a guest server is ready")
	publishSecret := flag.String("publish-secret", "", "bearer token sent with -publish-url requests")
	lanDiscovery := flag.Bool("lan-discovery", false, "announce the first forwarded port as a Minecraft LAN server")
	lanMotd := flag.String("lan-motd", "", "MOTD text for the Minecraft LAN announcement")
	flag.Parse()

	parsedLogLevel, err := logging.ParseLevel(*logLevel)
	if err != nil {
		return fmt.Errorf("parse log level: %w", err)
	}
	logging.SetLevel(parsedLogLevel)

	transportMode, err := peer.ParseTransportMode(*transportFlag)
	if err != nil {
		return fmt.Errorf("parse transport mode: %w", err)
	}
	if err := validateTransportForServer(transportMode, *serveMode || *guestServe || *unboundGuestServe); err != nil {
		return err
	}

	authMode, err := api.ParseShareAuthMode(*shareAuthMode)
	if err != nil {
		return fmt.Errorf("parse share auth mode: %w", err)
	}

	// Accountless modes create their own identity, and the login commands run on
	// a machine that has nothing yet, so both initialize a missing config file
	// instead of treating it as an error.
	accountless := *customServe || *customConnect != "" || *unboundGuestServe || *configURL != "" || *shareGuest
	bootstrapsConfig := accountless || *interactiveLogin || *loginQRCode || *refreshLogin || *loginMobile != ""
	var cfg *auth.Config
	if bootstrapsConfig {
		cfg, err = auth.LoadOrInitConfigFile(*configPath)
	} else {
		cfg, err = auth.LoadConfigFile(*configPath)
	}
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// A custom verification code comes from -custom-code, -guest-custom-code,
	// or the config file, in that order. Any custom code switches the share
	// authorization to custom mode unless "both" was requested explicitly.
	customCode := firstNonEmpty(*customCodeFlag, *guestCustomCode, cfg.CustomCode)
	if (customCode != "" || *customServe) && authMode == api.ShareAuthTemporary {
		authMode = api.ShareAuthCustom
	}
	if customCode != "" {
		if err := api.ValidateCustomShareCode(customCode); err != nil {
			return fmt.Errorf("validate custom code: %w", err)
		}
	}
	if *customServe && customCode == "" {
		customCode, err = api.GenerateCustomShareCode()
		if err != nil {
			return fmt.Errorf("generate custom code: %w", err)
		}
		logging.Infof("generated custom verification code: %s", customCode)
	}
	shareOptions := guestShareOptions{
		ControlID:     *guestControlID,
		AuthMode:      authMode,
		CustomCode:    customCode,
		ConfigPath:    *configPath,
		PublishURL:    *publishURL,
		PublishSecret: *publishSecret,
	}
	if *customServe {
		*unboundGuestServe = true
	}

	secPolicy, err := buildSecurityPolicy(cfg, *allowLAN, *allowedPortsFlag)
	if err != nil {
		return fmt.Errorf("configure security policy: %w", err)
	}

	client := api.NewClient(cfg)
	targetSessions := determineTargetSessions(*sessionsFlag, cfg.Sessions)
	if targetSessions > maxRelaySessions {
		return fmt.Errorf("sessions must not exceed %d", maxRelaySessions)
	}

	if *refreshLogin {
		return doRefreshLogin(client, cfg, *configPath, *loginQRCodeTimeout)
	}
	if *listDevices {
		return doListDevices(client)
	}
	if *guestTest {
		return doGuestTest(client)
	}
	if *userInfo {
		return doUserInfo(client)
	}
	if *interactiveLogin {
		return doInteractiveLogin(client, cfg, *configPath, *loginQRCodeTimeout, *loginCountryCode)
	}
	if *loginMobile != "" {
		return doMobileLogin(client, cfg, *configPath, *loginCountryCode, *loginMobile)
	}
	if *loginQRCode {
		return doLoginQRCode(client, cfg, *configPath, *loginQRCodeTimeout)
	}
	if *shareControlMode {
		if *shareID == "" {
			return fmt.Errorf("-share-id is required")
		}
		response, err := client.GetShareControlMode(*shareID)
		if err != nil {
			return fmt.Errorf("query share control mode: %w", err)
		}
		log.Printf("share control mode query complete: code=%v", response["code"])
		return nil
	}

	// -custom-connect is a share join whose ID/code may also come from the
	// config file, so a distributed client can start without any flags.
	if *customConnect != "" {
		if cfg.JWT != "" {
			*shareJoin = true
		} else {
			*shareGuest = true
		}
		*shareID = *customConnect
	}
	usesShareRoom := *shareJoin || *shareGuest || *shareConfirmation
	if usesShareRoom {
		*shareID = firstNonEmpty(*shareID, cfg.ShareID)
		*shareCode = firstNonEmpty(*shareCode, customCode, cfg.ShareCode)
		if *shareID == "" {
			return fmt.Errorf("-share-id is required")
		}
		if (*shareJoin || *shareGuest) && *shareCode == "" {
			return fmt.Errorf("-share-code is required")
		}
		if *shareJoin && cfg.JWT == "" {
			*shareJoin = false
			*shareGuest = true
		}
	}

	serverModes := 0
	for _, enabled := range []bool{*serveMode, *guestServe, *unboundGuestServe} {
		if enabled {
			serverModes++
		}
	}
	if serverModes > 1 {
		return fmt.Errorf("only one of -serve, -guest-serve, -unbound-guest-serve, or -custom-serve can be used")
	}
	if serverModes > 0 && *configURL != "" {
		return fmt.Errorf("-config-url selects the controller role and cannot be combined with a server mode")
	}
	if serverModes > 0 && usesShareRoom {
		return fmt.Errorf("share join flags cannot be combined with a server mode")
	}
	if *unboundGuestServe {
		rules, err := configuredRules(cfg, *ruleIDFlag, *mappingFlag, *localHost, *localPort, *remoteHost, *remotePort)
		if err != nil {
			return fmt.Errorf("configure mappings: %w", err)
		}
		// A fixed custom code has to keep its published identity, so that mode
		// starts as a single session and grows in band once a controller
		// reports a relay. Plain pooled mode still mints every room up front,
		// which keeps -room-file usable for controllers that join by hand.
		if targetSessions > 1 && !*customServe {
			// Each pooled session needs its own guest identity and room; the
			// unbound guest server is the only mode that can create them.
			return doMultiSessionUnboundGuestServe(cfg, rules, *roomFile, shareOptions, secPolicy, targetSessions)
		}
		return doUnboundGuestServe(client, cfg, rules, *roomFile, shareOptions, secPolicy, targetSessions)
	}
	if *guestServe {
		rules, err := configuredRules(cfg, *ruleIDFlag, *mappingFlag, *localHost, *localPort, *remoteHost, *remotePort)
		if err != nil {
			return fmt.Errorf("configure mappings: %w", err)
		}
		return doGuestServe(client, cfg, rules, *roomFile, shareOptions, secPolicy, targetSessions)
	}
	if *serveMode {
		if *deviceID != "" {
			return fmt.Errorf("-device cannot be combined with -serve; the server uses this config's device")
		}
		rules, err := configuredRules(cfg, *ruleIDFlag, *mappingFlag, *localHost, *localPort, *remoteHost, *remotePort)
		if err != nil {
			return fmt.Errorf("configure mappings: %w", err)
		}
		return doServe(client, cfg, rules, *roomFile, secPolicy, targetSessions)
	}

	if *configURL != "" {
		return runRemoteConfigController(client, cfg, secPolicy, remoteConfigOptions{
			url:           *configURL,
			transportMode: transportMode,
			lanDiscovery:  *lanDiscovery,
			lanMotd:       *lanMotd,
			ruleID:        *ruleIDFlag,
			mapping:       *mappingFlag,
			localHost:     *localHost,
			localPort:     *localPort,
			remoteHost:    *remoteHost,
			remotePort:    *remotePort,
			capability:    *capFlag,
		})
	}

	// A controller can drive several pooled sessions at once when given one
	// share per session (comma-separated flags or a multi-share room file).
	multiShares, err := multiSessionShares(*roomFile, *shareJoin, *shareGuest, *shareID, *shareCode)
	if err != nil {
		return err
	}
	if len(multiShares) > 1 {
		rules, err := configuredRules(cfg, *ruleIDFlag, *mappingFlag, *localHost, *localPort, *remoteHost, *remotePort)
		if err != nil {
			return fmt.Errorf("configure mappings: %w", err)
		}
		return doMultiSessionController(client, cfg, rules, multiShares, multiSessionControllerOptions{
			transportMode: transportMode,
			useGuest:      *shareGuest,
			shareIDs:      *shareID,
			shareCodes:    *shareCode,
		}, secPolicy)
	}

	if err := runController(client, cfg, secPolicy, controllerOptions{
		deviceID:          *deviceID,
		allowSelf:         *allowSelf,
		controlDeviceID:   *controlDeviceID,
		roomFile:          *roomFile,
		shareJoin:         *shareJoin,
		shareConfirmation: *shareConfirmation,
		shareControlID:    *shareControlID,
		shareGuest:        *shareGuest,
		shareID:           *shareID,
		shareCode:         *shareCode,
		ruleID:            *ruleIDFlag,
		mapping:           *mappingFlag,
		localHost:         *localHost,
		localPort:         *localPort,
		remoteHost:        *remoteHost,
		remotePort:        *remotePort,
		capability:        *capFlag,
		transportMode:     transportMode,
		pckSweep:          *pckSweep,
		mixKCP:            *mixkcpMode,
		targetSessions:    targetSessions,
		lanDiscovery:      *lanDiscovery,
		lanMotd:           *lanMotd,
		configPath:        *configPath,
	}); err != nil {
		return err
	}
	return nil
}

func validateTransportForServer(mode peer.TransportMode, serverMode bool) error {
	if serverMode && mode != peer.TransportAuto {
		return fmt.Errorf("-transport relay is supported only by the controller, not server mode")
	}
	return nil
}

type controllerOptions struct {
	deviceID          string
	allowSelf         bool
	controlDeviceID   string
	roomFile          string
	shareJoin         bool
	shareConfirmation bool
	shareControlID    string
	shareGuest        bool
	shareID           string
	shareCode         string
	ruleID            string
	mapping           string
	localHost         string
	localPort         string
	remoteHost        string
	remotePort        string
	capability        string
	transportMode     peer.TransportMode
	pckSweep          bool
	mixKCP            bool
	targetSessions    int
	// rules, when non-nil, replaces the config/flag derived mappings (remote
	// configuration mode).
	rules []tunnel.Rule
	// lanDiscovery announces the first forwarded port as a Minecraft LAN
	// server once the tunnel is up.
	lanDiscovery bool
	lanMotd      string
	configPath   string
}

const relayTransportTimeout = 30 * time.Second

// errSignalingClosed reports a signaling connection that ended without a local
// shutdown request. It is a runtime failure, so the process must not exit 0
// and let service managers mistake a dropped network path for a clean stop.
var errSignalingClosed = errors.New("signaling connection closed unexpectedly")

func runController(client *api.Client, cfg *auth.Config, secPolicy tunnel.SecurityPolicy, options controllerOptions) error {
	usesShareRoom := options.shareJoin || options.shareGuest || options.shareConfirmation

	targetDevID := options.deviceID
	if targetDevID == "" {
		targetDevID = cfg.DeviceID
	}

	if options.roomFile == "" && !usesShareRoom && (targetDevID == "" || (targetDevID == cfg.DeviceID && !options.allowSelf)) {
		return fmt.Errorf("target device must differ from this machine (use -device)")
	}
	rules := options.rules
	var err error
	if rules == nil {
		rules, err = configuredRules(cfg, options.ruleID, options.mapping, options.localHost, options.localPort, options.remoteHost, options.remotePort)
		if err != nil {
			return fmt.Errorf("configure mappings: %w", err)
		}
	}

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
				return fmt.Errorf("join guest share room: %w; the API only exposes "+
					"shares to logged-in users, so the controlling side cannot join "+
					"with a guest identity: run %q on this machine and retry, the "+
					"served side can stay accountless", err, "uulink -login")
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

	gateway := room.SignalingServer
	if gateway == "" && len(room.SignalingList) > 0 {
		gateway = room.SignalingList[0]
	}

	// Step 2: connect to signaling gateway
	logging.Debugf("connecting to signaling gateway %s", gateway)
	sig, err := signaling.Connect(&signaling.ConnectConfig{
		GatewayURL:  gateway,
		NRDAuth:     room.Token,
		Controlling: true,
	})
	if err != nil {
		return fmt.Errorf("signaling connect: %w", err)
	}
	defer sig.Close()

	// Wait for namespace confirmation
	select {
	case <-sig.NamespaceConnected():
	case <-time.After(5 * time.Second):
		logging.Warnf("signaling namespace connect timeout")
	case <-sig.Done():
		return fmt.Errorf("signaling closed before namespace connection")
	}

	// Log forward_setting events (server pushes these after answer)
	sig.On("forward_setting", func(ev *signaling.Event) {
		if len(ev.Args) > 0 {
			logging.Debugf("[signaling] forward_setting received (%d bytes)", len(ev.Args[0]))
		}
	})

	if options.capability != "" {
		if err := peer.CapOverride(options.capability); err != nil {
			return fmt.Errorf("cap override: %w", err)
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
		return fmt.Errorf("-pck-sweep and -mixkcp require at least one port mapping")
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
	var primarySession tunnel.Session
	var expandPool *tunnel.AdaptiveSessionPool
	p, err := peer.NewController(&peer.Config{
		Signal:        sig,
		DeviceID:      peerDeviceID,
		AppControlID:  controllerAppControlID,
		Passive:       room.IsRoomFileController,
		TransportMode: options.transportMode,
		OnSignalData: func(data []byte) {
			if tun != nil {
				if frame := tunnel.DecodeFrameForTunnel(data); frame != nil && primarySession != nil {
					if expandPool != nil {
						expandPool.Pool().BindStream(frame.RuleID, frame.StreamID, primarySession)
					}
				}
				tun.HandleMessage(data)
			}
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
	adaptivePool := tunnel.NewAdaptiveSessionPool(options.targetSessions, tunnel.PolicyStreamLeastLoaded,
		func(target int) error {
			return expandControllerPool(client, cfg, negotiator, p, tun, expandPool, expandSet, target, options.transportMode, secPolicy)
		})
	expandPool = adaptivePool
	primarySession = tunnel.NewSimpleSession("primary", &peerSender{peer: p}, nil)
	adaptivePool.Pool().AddSession(primarySession)
	p.OnTextMessage(func(data []byte) { negotiator.handle(data) })
	p.OnModeChange(adaptivePool.OnModeDetected)

	tun = tunnel.NewTunnelWithRules(rules, adaptivePool)
	tun.SetSecurityPolicy(secPolicy)
	runErr := make(chan error, 1)
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
		logging.Errorf("peer error: %s", truncate(string(ev.Args[0]), 150))
	})

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(interrupt)

	if p.TransportMode() == peer.TransportRelay {
		select {
		case <-tunnelReady:
			logging.Infof("transport relay ready")
		case <-time.After(relayTransportTimeout):
			return fmt.Errorf("transport relay required: connection not ready within %s", relayTransportTimeout)
		case <-interrupt:
			logging.Infof("interrupted, shutting down")
			return nil
		case <-sig.Done():
			return errSignalingClosed
		case err := <-runErr:
			return err
		}
	}

	select {
	case <-interrupt:
		logging.Infof("interrupted, shutting down")
	case <-sig.Done():
		return errSignalingClosed
	case err := <-runErr:
		return err
	}
	return nil
}

func doServe(client *api.Client, cfg *auth.Config, rules []tunnel.Rule, roomFile string, policy tunnel.SecurityPolicy, targetSessions int) error {
	hostname, err := cfg.EffectiveHostname()
	if err != nil {
		return fmt.Errorf("resolve hostname: %w", err)
	}
	logging.Debugf("registering controlled device %q", hostname)
	if _, err := client.InitMacDevice(hostname); err != nil {
		return fmt.Errorf("register controlled device: %w", err)
	}
	if _, err := client.SetMacControllable(true); err != nil {
		return fmt.Errorf("enable controlled device: %w", err)
	}

	logging.Debugf("creating controlled room")
	room, err := client.CreateRoom()
	if err != nil {
		return fmt.Errorf("create room: %w", err)
	}
	return serveRoom(client, cfg, rules, room, roomFile, nil, guestShareOptions{}, policy, targetSessions)
}

type guestShareOptions struct {
	ControlID  string
	AuthMode   api.ShareAuthMode
	CustomCode string
	// ConfigPath, when set, receives the share ID / custom code and the
	// unbound device identity so the next start reuses them.
	ConfigPath string
	// PublishURL, when set, receives the share configuration as JSON.
	PublishURL    string
	PublishSecret string
}

func doGuestServe(client *api.Client, cfg *auth.Config, rules []tunnel.Rule, roomFile string, shareOptions guestShareOptions, policy tunnel.SecurityPolicy, targetSessions int) error {
	session, err := client.CreateGuest()
	if err != nil {
		return fmt.Errorf("create guest: %w", err)
	}
	room, err := client.CreateGuestRoom(session)
	if err != nil {
		return fmt.Errorf("create guest room: %w", err)
	}
	return serveRoom(client, cfg, rules, room, roomFile, session, shareOptions, policy, targetSessions)
}

func doUnboundGuestServe(client *api.Client, cfg *auth.Config, rules []tunnel.Rule, roomFile string, shareOptions guestShareOptions, policy tunnel.SecurityPolicy, targetSessions int) error {
	hostname, err := cfg.EffectiveHostname()
	if err != nil {
		return fmt.Errorf("resolve hostname: %w", err)
	}
	session, identity, err := client.CreateUnboundGuest(hostname)
	if err != nil {
		return fmt.Errorf("create unbound guest: %w", err)
	}
	cfg.ClientID = identity.ClientID
	cfg.DeviceID = identity.DeviceID
	cfg.Platform = 1
	// CreateUnboundGuest recorded the identity in cfg.UnboundClientID and
	// cfg.UnboundDeviceID; persist it so the assistance ID survives restarts.
	if shareOptions.ConfigPath != "" {
		if err := auth.SaveConfigFile(shareOptions.ConfigPath, cfg); err != nil {
			return fmt.Errorf("save unbound device identity: %w", err)
		}
	}
	logging.Debugf("unbound guest identity ready")

	room, err := client.CreateGuestRoom(session)
	if err != nil {
		return fmt.Errorf("create guest room: %w", err)
	}
	return serveRoom(client, cfg, rules, room, roomFile, session, shareOptions, policy, targetSessions)
}

func serveRoom(client *api.Client, cfg *auth.Config, rules []tunnel.Rule, room *api.RoomConnectionInfo, roomFile string, guestSession *api.GuestSession, shareOptions guestShareOptions, policy tunnel.SecurityPolicy, targetSessions int) error {
	if roomFile != "" {
		roomInfoFile := roomFile
		if guestSession != nil {
			roomInfoFile = roomFile + ".room"
		}
		if err := saveRoomFile(roomInfoFile, room); err != nil {
			return fmt.Errorf("save room file: %w", err)
		}
		logging.Debugf("saved room connection info to %s", roomInfoFile)
	}

	gateway := room.SignalingServer
	if gateway == "" && len(room.SignalingList) > 0 {
		gateway = room.SignalingList[0]
	}
	logging.Debugf("connecting to signaling gateway %s", gateway)
	sig, err := signaling.Connect(&signaling.ConnectConfig{
		GatewayURL:  gateway,
		NRDAuth:     room.Token,
		Controlling: false,
	})
	if err != nil {
		return fmt.Errorf("signaling connect: %w", err)
	}
	defer sig.Close()

	select {
	case <-sig.NamespaceConnected():
	case <-time.After(5 * time.Second):
		return fmt.Errorf("signaling namespace connect timeout")
	case <-sig.Done():
		return fmt.Errorf("signaling closed before namespace connection")
	}

	var share *api.GuestShareInfo
	if guestSession != nil {
		if _, err := client.GuestSetDeviceControllable(guestSession, true); err != nil {
			return fmt.Errorf("set guest device controllable: %w", err)
		}
		share, err = waitForGuestConnectID(client, guestSession)
		if err != nil {
			return fmt.Errorf("get guest share info: %w", err)
		}
		share, err = ensureGuestShareCode(client, guestSession, share, shareOptions)
		if err != nil {
			return fmt.Errorf("prepare guest share code: %w", err)
		}
		controlModeID := shareOptions.ControlID
		if controlModeID == "" {
			controlModeID = share.ConnectID
		}
		if _, err := client.GuestShareUploadControlMode(guestSession,
			api.NewGuestShareUploadControlModeRequest(controlModeID, true, shareOptions.AuthMode)); err != nil {
			return fmt.Errorf("upload guest control mode: %w", err)
		}
	}

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
			logging.Errorf("[signaling] controlled bmsg_push parse error: %v", err)
			return
		}

		if guestSession != nil && push.Type == "remote_control" {
			if push.Data.ControlID == "" {
				logging.Warnf("remote control push has no control_id")
				return
			}
			updatedShare, err := uploadGuestShareCode(client, guestSession, share, push.Data.ControlID, push.Data.Salt, shareOptions)
			if err != nil {
				logging.Errorf("upload remote-control guest share sign failed: %v", err)
				return
			}
			share = updatedShare
			if roomFile != "" {
				if err := saveGuestShareFile(roomFile, share); err != nil {
					logging.Errorf("update remote-control guest share file failed: %v", err)
				}
			}
			_, err = client.GuestShareConfirmation(guestSession, &api.GuestShareConfirmationRequest{
				ControlID:    push.Data.ControlID,
				AllowControl: true,
				NeedPassword: shareOptions.AuthMode != api.ShareAuthCustom,
			})
			if err != nil {
				logging.Errorf("confirm remote control failed: %v", err)
				return
			}
			logging.Infof("remote control confirmed")
			return
		}

		if push.Type == "get_control_mode" {
			logging.Debugf("get_control_mode received")
			if guestSession != nil && push.Data.ControlID != "" {
				updatedShare, err := uploadGuestShareCode(client, guestSession, share, push.Data.ControlID, push.Data.Salt, shareOptions)
				if err != nil {
					logging.Errorf("upload pushed guest share sign failed: %v", err)
					return
				}
				share = updatedShare
				controlModeRequest := api.NewGuestShareUploadControlModeRequest(push.Data.ControlID, true, shareOptions.AuthMode)
				if _, err := client.GuestShareUploadControlMode(guestSession, controlModeRequest); err != nil {
					logging.Errorf("upload pushed control mode failed: %v", err)
				} else {
					logging.Debugf("uploaded pushed control mode")
				}
				share.ControlID = push.Data.ControlID
				if roomFile != "" {
					if err := saveGuestShareFile(roomFile, share); err != nil {
						logging.Errorf("update guest share control_id file failed: %v", err)
					} else {
						logging.Debugf("updated guest share control_id file")
					}
				}
			}
			return
		}

		logging.Debugf("[signaling] controlled bmsg_push type=%q", push.Type)
	})

	if guestSession != nil {
		if roomFile != "" {
			if err := saveGuestShareFile(roomFile, share); err != nil {
				return fmt.Errorf("save guest share file: %w", err)
			}
			logging.Debugf("saved guest share info to %s", roomFile)
		}
		if shareOptions.AuthMode == api.ShareAuthCustom {
			logging.Infof("custom assistance ready: connect_id=%s custom_code=%s", share.ConnectID, share.ConnectCode)
			logging.Infof("client command: uulink -custom-connect %s -custom-code %s", share.ConnectID, share.ConnectCode)
		} else {
			logging.Infof("guest share ready: connect_id=%s connect_code=%s", share.ConnectID, share.ConnectCode)
		}
		if shareOptions.ConfigPath != "" && (cfg.ShareID != share.ConnectID || cfg.CustomCode != shareOptions.CustomCode) {
			// Remember the share so the same ID and custom code are reused
			// next time this server starts.
			cfg.ShareID = share.ConnectID
			cfg.CustomCode = shareOptions.CustomCode
			if err := auth.SaveConfigFile(shareOptions.ConfigPath, cfg); err != nil {
				return fmt.Errorf("save share identity: %w", err)
			}
		}
		if shareOptions.PublishURL != "" {
			if err := publishShareInfo(shareOptions.PublishURL, shareOptions.PublishSecret, share, rules); err != nil {
				return fmt.Errorf("publish share info: %w", err)
			}
		}
	}

	var tun *tunnel.Tunnel
	var primarySession tunnel.Session
	var adaptivePool *tunnel.AdaptiveSessionPool
	p, err := peer.NewControlled(&peer.Config{
		Signal: sig,
		OnSignalData: func(data []byte) {
			if tun != nil {
				if frame := tunnel.DecodeFrameForTunnel(data); frame != nil && primarySession != nil {
					adaptivePool.Pool().BindStream(frame.RuleID, frame.StreamID, primarySession)
				}
				tun.HandleMessage(data)
			}
		},
	})
	if err != nil {
		return fmt.Errorf("create controlled peer: %w", err)
	}
	defer p.Close()

	if room.ReportURL != "" && room.ReportToken != "" {
		if _, err := client.ReportIP(room); err != nil {
			logging.Debugf("report relay IP: %v", err)
		}
		if _, err := client.ReportEchoServers(room); err != nil {
			logging.Debugf("report relay echo servers: %v", err)
		}
	}

	// The controller drives pool growth: it is the side that can tell whether
	// the connection landed on a relay. Each extra session needs a room of its
	// own, which this side mints on request.
	adaptivePool = tunnel.NewAdaptiveSessionPool(targetSessions, tunnel.PolicyStreamLeastLoaded, nil)
	primarySession = tunnel.NewSimpleSession("primary", &peerSender{peer: p}, nil)
	adaptivePool.Pool().AddSession(primarySession)
	p.OnModeChange(adaptivePool.OnModeDetected)

	tun = tunnel.NewTunnelWithRules(rules, adaptivePool)
	tun.SetSecurityPolicy(policy)

	expandSet := newSessionSet()
	defer expandSet.closeAll()
	p.OnTextMessage(serveExpandRequests(p, targetSessions-1, func(extra int) ([]expandShare, error) {
		return mintExpansionRooms(cfg, tun, adaptivePool, expandSet, shareOptions, policy, extra)
	}))
	runErr := make(chan error, 1)
	p.OnFileChannelOpen(func() {
		if len(rules) > 0 {
			if err := tun.Start(); err != nil {
				select {
				case runErr <- fmt.Errorf("start tunnel: %w", err):
				default:
				}
				return
			}
			logActiveMappings("reverse port forwarding active", rules)
		} else {
			logging.Infof("inbound port mapping active (no reverse mappings configured)")
		}
		logSecurityPolicy(policy)
	})
	defer tun.Stop()

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(interrupt)
	select {
	case <-interrupt:
		logging.Infof("interrupted, shutting down")
	case <-sig.Done():
		return errSignalingClosed
	case err := <-runErr:
		return err
	}
	return nil
}

func waitForGuestConnectID(client *api.Client, session *api.GuestSession) (*api.GuestShareInfo, error) {
	var lastErr error
	for range 5 {
		share, err := client.GetGuestShareInfo(session)
		if err == nil && share.ConnectID != "" {
			return share, nil
		} else if err != nil {
			lastErr = err
		} else {
			lastErr = fmt.Errorf("connect_id is empty")
		}
		time.Sleep(time.Second)
	}
	return nil, lastErr
}

func ensureGuestShareCode(client *api.Client, session *api.GuestSession, share *api.GuestShareInfo, shareOptions guestShareOptions) (*api.GuestShareInfo, error) {
	controlID := share.ConnectID
	if shareOptions.ControlID != "" {
		controlID = shareOptions.ControlID
	}
	temporaryCode := share.ConnectCode
	if temporaryCode == "" {
		var err error
		temporaryCode, err = api.GenerateSharePassCode()
		if err != nil {
			return nil, err
		}
	}
	customCode := shareOptions.CustomCode
	if customCode == "" && shareOptions.AuthMode != api.ShareAuthTemporary {
		var err error
		customCode, err = api.GenerateCustomShareCode()
		if err != nil {
			return nil, err
		}
	}
	request := api.NewGuestShareUploadSignRequest(controlID, temporaryCode, customCode, shareOptions.AuthMode)
	if _, err := client.GuestShareUploadSign(session, request); err != nil {
		return nil, err
	}
	uploadedCode := temporaryCode

	refreshed, err := client.GetGuestShareInfo(session)
	if err != nil {
		return nil, fmt.Errorf("refresh after upload sign: %w", err)
	}
	if refreshed.ConnectID != "" && refreshed.ConnectID != share.ConnectID {
		return nil, fmt.Errorf("connect_id changed after upload sign")
	}
	if refreshed.ConnectCode != "" {
		temporaryCode = refreshed.ConnectCode
	}
	logging.Debugf("guest share code refresh: uploaded_len=%d returned_len=%d changed=%v",
		len(uploadedCode), len(refreshed.ConnectCode), refreshed.ConnectCode != uploadedCode)
	refreshed.ConnectID = share.ConnectID
	refreshed.TemporaryCode = temporaryCode
	refreshed.CustomCode = customCode
	refreshed.ConnectCode = api.ShareJoinCode(temporaryCode, customCode, shareOptions.AuthMode)
	if shareOptions.ControlID != "" {
		refreshed.ControlID = shareOptions.ControlID
	}
	return refreshed, nil
}

func uploadGuestShareCode(client *api.Client, session *api.GuestSession, share *api.GuestShareInfo, controlID, salt string, shareOptions guestShareOptions) (*api.GuestShareInfo, error) {
	temporaryCode := share.TemporaryCode
	if temporaryCode == "" && shareOptions.AuthMode != api.ShareAuthCustom {
		temporaryCode = share.ConnectCode
	}
	if temporaryCode == "" {
		var err error
		temporaryCode, err = api.GenerateSharePassCode()
		if err != nil {
			return nil, err
		}
	}
	customCode := share.CustomCode
	if customCode == "" && shareOptions.AuthMode != api.ShareAuthTemporary {
		var err error
		customCode, err = api.GenerateCustomShareCode()
		if err != nil {
			return nil, err
		}
	}
	var request *api.GuestShareUploadSignRequest
	if salt != "" {
		request = api.NewGuestShareUploadSignRequestWithSalt(controlID, salt, temporaryCode, customCode, shareOptions.AuthMode)
		logging.Debugf("uploading salted guest share sign: control_id_len=%d salt_len=%d", len(controlID), len(salt))
	} else {
		request = api.NewGuestShareUploadSignRequest(controlID, temporaryCode, customCode, shareOptions.AuthMode)
	}
	if _, err := client.GuestShareUploadSign(session, request); err != nil {
		return nil, err
	}
	uploadedCode := temporaryCode
	refreshed, err := client.GetGuestShareInfo(session)
	if err != nil {
		return nil, fmt.Errorf("refresh after pushed upload sign: %w", err)
	}
	if refreshed.ConnectID != "" && refreshed.ConnectID != share.ConnectID {
		return nil, fmt.Errorf("connect_id changed after pushed upload sign")
	}
	if refreshed.ConnectCode != "" {
		temporaryCode = refreshed.ConnectCode
	}
	logging.Debugf("pushed guest share code refresh: uploaded_len=%d returned_len=%d changed=%v",
		len(uploadedCode), len(refreshed.ConnectCode), refreshed.ConnectCode != uploadedCode)
	refreshed.ConnectID = share.ConnectID
	refreshed.TemporaryCode = temporaryCode
	refreshed.CustomCode = customCode
	refreshed.ConnectCode = api.ShareJoinCode(temporaryCode, customCode, shareOptions.AuthMode)
	refreshed.ControlID = controlID
	return refreshed, nil
}

type roomFileInfo struct {
	SignalingServer string   `json:"signaling_server"`
	SignalingList   []string `json:"signaling_list"`
	Token           string   `json:"token"`
}

type guestShareFileInfo struct {
	ConnectID     string `json:"connect_id"`
	ConnectCode   string `json:"connect_code"`
	TemporaryCode string `json:"temporary_code,omitempty"`
	CustomCode    string `json:"custom_code,omitempty"`
	ControlID     string `json:"control_id,omitempty"`
}

func saveGuestShareFile(path string, share *api.GuestShareInfo) error {
	data, err := json.Marshal(guestShareFileInfo{
		ConnectID:     share.ConnectID,
		ConnectCode:   share.ConnectCode,
		TemporaryCode: share.TemporaryCode,
		CustomCode:    share.CustomCode,
		ControlID:     share.ControlID,
	})
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func saveRoomFile(path string, room *api.RoomConnectionInfo) error {
	data, err := json.Marshal(roomFileInfo{
		SignalingServer: room.SignalingServer,
		SignalingList:   room.SignalingList,
		Token:           room.Token,
	})
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func loadRoomFile(path string) (*api.RoomConnectionInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var info roomFileInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return nil, err
	}
	if info.Token == "" || (info.SignalingServer == "" && len(info.SignalingList) == 0) {
		return nil, fmt.Errorf("room file has no signaling token or gateway")
	}
	return &api.RoomConnectionInfo{
		SignalingServer: info.SignalingServer,
		SignalingList:   info.SignalingList,
		Token:           info.Token,
	}, nil
}

func configuredRules(cfg *auth.Config, ruleIDFlag, mappingFlag, localHost, cliLocalPort, remoteHost, cliRemotePort string) ([]tunnel.Rule, error) {
	var rules []tunnel.Rule
	seen := make(map[string]bool)

	appendRule := func(rule tunnel.Rule) error {
		if rule.ID == "" {
			rule.ID = generateRuleID()
		}
		if _, err := strconv.ParseUint(rule.ID, 10, 64); err != nil {
			return fmt.Errorf("rule %s: rule-id must be numeric: %w", rule.ID, err)
		}
		if rule.LocalPort <= 0 || rule.TargetPort <= 0 {
			return fmt.Errorf("rule %s: local_port and remote_port must be positive", rule.ID)
		}
		if seen[rule.ID] {
			return fmt.Errorf("duplicate rule ID %s", rule.ID)
		}
		seen[rule.ID] = true
		rules = append(rules, rule)
		return nil
	}

	for _, mapping := range cfg.Mappings {
		lHost := mapping.LocalHost
		if lHost == "" {
			lHost = "127.0.0.1"
		}
		rHost := mapping.RemoteHost
		if rHost == "" {
			rHost = "127.0.0.1"
		}

		var pairs []tunnel.PortPair
		var err error
		switch {
		case mapping.Range != "":
			pairs, err = tunnel.ParsePortMappingSpec(mapping.Range)
		case mapping.LocalRange != "" || mapping.RemoteRange != "":
			lSpec := mapping.LocalRange
			if lSpec == "" && mapping.LocalPort != 0 {
				lSpec = strconv.Itoa(mapping.LocalPort)
			}
			rSpec := mapping.RemoteRange
			if rSpec == "" && mapping.RemotePort != 0 {
				rSpec = strconv.Itoa(mapping.RemotePort)
			}
			pairs, err = tunnel.ExpandPortRange(lSpec, rSpec)
		case mapping.LocalPort != 0 && mapping.RemotePort != 0:
			pairs = []tunnel.PortPair{{LocalPort: mapping.LocalPort, RemotePort: mapping.RemotePort}}
		default:
			return nil, fmt.Errorf("mapping must specify local and remote ports or ranges")
		}
		if err != nil {
			return nil, fmt.Errorf("mapping rule: %w", err)
		}

		for _, pair := range pairs {
			rID := mapping.RuleID
			if len(pairs) > 1 {
				rID = "" // generate unique numeric rule IDs across ranges
			}
			if err := appendRule(tunnel.Rule{
				ID:         rID,
				LocalHost:  lHost,
				LocalPort:  pair.LocalPort,
				TargetHost: rHost,
				TargetPort: pair.RemotePort,
			}); err != nil {
				return nil, err
			}
		}
	}

	if mappingFlag != "" {
		pairs, err := tunnel.ParsePortMappingSpec(mappingFlag)
		if err != nil {
			return nil, fmt.Errorf("-mapping: %w", err)
		}
		for _, pair := range pairs {
			rID := ruleIDFlag
			if len(pairs) > 1 {
				rID = ""
			}
			if err := appendRule(tunnel.Rule{
				ID:         rID,
				LocalHost:  localHost,
				LocalPort:  pair.LocalPort,
				TargetHost: remoteHost,
				TargetPort: pair.RemotePort,
			}); err != nil {
				return nil, err
			}
		}
	}

	if cliLocalPort != "" || cliRemotePort != "" {
		if cliLocalPort == "" || cliRemotePort == "" {
			return nil, fmt.Errorf("both -local and -remote-port are required for a command-line mapping")
		}
		if len(cfg.Mappings) > 0 && ruleIDFlag != "" {
			return nil, fmt.Errorf("-rule-id cannot be applied globally when config mappings define their own rule_id")
		}
		pairs, err := tunnel.ExpandPortRange(cliLocalPort, cliRemotePort)
		if err != nil {
			return nil, fmt.Errorf("cli port mapping: %w", err)
		}
		for _, pair := range pairs {
			rID := ruleIDFlag
			if len(pairs) > 1 {
				rID = ""
			}
			if err := appendRule(tunnel.Rule{
				ID:         rID,
				LocalHost:  localHost,
				LocalPort:  pair.LocalPort,
				TargetHost: remoteHost,
				TargetPort: pair.RemotePort,
			}); err != nil {
				return nil, err
			}
		}
	}
	return rules, nil
}

func logActiveMappings(prefix string, rules []tunnel.Rule) {
	for _, rule := range rules {
		logging.Infof("%s: %s:%d -> peer-target %s:%d (rule %s)",
			prefix, rule.LocalHost, rule.LocalPort, rule.TargetHost, rule.TargetPort, rule.ID)
	}
}

func generateRuleID() string {
	var b [8]byte
	if _, err := crand.Read(b[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	v := binary.BigEndian.Uint64(b[:]) & ((1 << 63) - 1)
	if v == 0 {
		v = uint64(time.Now().UnixNano())
	}
	return strconv.FormatUint(v, 10)
}

func generateAppControlID() (string, error) {
	var b [16]byte
	if _, err := crand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// peerSender adapts peer.Peer to tunnel.FrameSender, wrapping frames in
// the signaling pb channel events.
type peerSender struct {
	peer *peer.Peer
}

func (s *peerSender) SendFrame(msg []byte) error {
	// PM protobuf messages are sent directly on FILE_DATA_CHANNEL.
	return s.peer.SendSignalPB(msg)
}

func doListDevices(client *api.Client) error {
	devices, err := client.GetDeviceList()
	if err != nil {
		return fmt.Errorf("get device list: %w", err)
	}

	fmt.Printf("%-24s %-16s %-14s %-8s %-12s %s\n", "DEVICE_ID", "NAME", "STATUS", "PLAT", "CLIENT_ID", "VERSION")
	fmt.Printf("%-24s %-16s %-14s %-8s %-12s %s\n", "--------", "----", "------", "----", "---------", "-------")
	for _, device := range devices {
		fmt.Printf("%-24s %-16s %-14s %-8d %-12s %s\n",
			device.DeviceID, device.Alias, device.Status, device.Platform, device.ClientID, device.VersionName)
	}
	return nil
}

func doUserInfo(client *api.Client) error {
	user, err := client.GetUserInfo()
	if err != nil {
		return fmt.Errorf("get user info: %w", err)
	}
	log.Printf("user info: nickname=%q user_id_len=%d keys=%v",
		user.Nickname, len(user.UserID), mapKeys(user.Raw))
	return nil
}

func doInteractiveLogin(client *api.Client, cfg *auth.Config, configPath string, qrTimeout time.Duration, defaultCountryCode string) error {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Select login method:")
	fmt.Println("  1. QR code scan (Recommended)")
	fmt.Println("  2. SMS verification code (Mobile)")
	fmt.Print("Enter choice [1/2, default 1]: ")
	choiceText, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read login method: %w", err)
	}
	choice := strings.TrimSpace(choiceText)
	switch choice {
	case "2", "mobile", "sms":
		return doMobileLogin(client, cfg, configPath, defaultCountryCode, "")
	default:
		return doLoginQRCode(client, cfg, configPath, qrTimeout)
	}
}

func doMobileLogin(client *api.Client, cfg *auth.Config, configPath, countryCode, mobile string) error {
	reader := bufio.NewReader(os.Stdin)
	if mobile == "" {
		fmt.Print("Enter mobile phone number: ")
		text, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("read mobile number: %w", err)
		}
		mobile = strings.TrimSpace(text)
		if mobile == "" {
			return fmt.Errorf("mobile phone number cannot be empty")
		}
	}
	if countryCode == "" {
		countryCode = "+86"
	}

	log.Printf("requesting SMS verification code for %s %s...", countryCode, mobile)
	resp, err := client.RequestMobileCode(countryCode, mobile)
	if err != nil {
		var responseErr *api.ResponseError
		if errors.As(err, &responseErr) {
			return fmt.Errorf("request SMS code failed: code=%d msg=%q (server may require captcha): %w",
				responseErr.Code, responseErr.Message, err)
		}
		return fmt.Errorf("request SMS code: %w", err)
	}
	log.Printf("SMS code request sent (code=%v msg=%q)", resp["code"], resp["msg"])

	fmt.Print("Enter SMS verification code: ")
	codeText, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read SMS code: %w", err)
	}
	code := strings.TrimSpace(codeText)
	if code == "" {
		return fmt.Errorf("verification code cannot be empty")
	}

	login, err := client.LoginByMobile(countryCode, mobile, code)
	if err != nil {
		var responseErr *api.ResponseError
		if errors.As(err, &responseErr) {
			return fmt.Errorf("mobile login failed: code=%d msg=%q: %w", responseErr.Code, responseErr.Message, err)
		}
		return fmt.Errorf("mobile login: %w", err)
	}

	token := login.Token
	refreshedState, err := persistLogin(client, cfg, configPath, token)
	if err != nil {
		return err
	}
	log.Printf("mobile login confirmed; JWT length=%d user_id_len=%d config=%s",
		len(token), len(refreshedState.UserID), configPath)
	return nil
}

func persistLogin(client *api.Client, cfg *auth.Config, configPath, token string) (*api.LoginState, error) {
	userID, err := api.JWTSubject(token)
	if err != nil {
		return nil, fmt.Errorf("decode login JWT: %w", err)
	}

	previousJWT, previousUserID, previousGuestID := cfg.JWT, cfg.UserID, cfg.GuestID
	cfg.JWT = token
	cfg.UserID = userID
	cfg.GuestID = ""
	state, err := client.GetLoginState()
	if err != nil || !state.Valid {
		cfg.JWT, cfg.UserID, cfg.GuestID = previousJWT, previousUserID, previousGuestID
		if err != nil {
			return nil, fmt.Errorf("validate refreshed login state: %w", err)
		}
		return nil, fmt.Errorf("refreshed login state is invalid")
	}
	if err := auth.SaveConfigFile(configPath, cfg); err != nil {
		cfg.JWT, cfg.UserID, cfg.GuestID = previousJWT, previousUserID, previousGuestID
		return nil, fmt.Errorf("save refreshed config: %w", err)
	}
	return state, nil
}

func doRefreshLogin(client *api.Client, cfg *auth.Config, configPath string, timeout time.Duration) error {
	state, err := client.GetLoginState()
	if err == nil && state.Valid {
		log.Printf("login state valid; no refresh needed (user_id_len=%d nickname=%q)",
			len(state.UserID), state.Nickname)
		return nil
	}
	if err != nil {
		var responseErr *api.ResponseError
		if !errors.As(err, &responseErr) {
			return fmt.Errorf("validate login state: %w", err)
		}
		log.Printf("login state invalid: %v", responseErr)
	} else {
		log.Printf("login state invalid: user info response has no user_id")
	}
	return doLoginQRCode(client, cfg, configPath, timeout)
}

// ensureBootstrapGuest returns a guest session usable for account bootstrap
// calls such as QR-code login.
//
// POST /guest/create sends this machine's device_id, and the server rejects it
// with code 1001 when that device was never registered. A fresh config.json has
// no device_id, so fall back to registering an accountless device first and
// persist the identity, which keeps later runs on the cheap path.
func ensureBootstrapGuest(client *api.Client, cfg *auth.Config, configPath, name string) (*api.GuestSession, error) {
	if cfg.DeviceID != "" && cfg.ClientID != "" && (cfg.Platform == 1 || runtime.GOOS == "windows") {
		session, err := client.CreateGuest()
		if err == nil {
			return session, nil
		}
		logging.Debugf("guest create with configured identity failed, registering a device: %v", err)
	}
	session, identity, err := client.CreateUnboundGuest(name)
	if err != nil {
		return nil, err
	}
	if identity != nil {
		cfg.ClientID = identity.ClientID
		cfg.DeviceID = identity.DeviceID
		cfg.Platform = 1
		if configPath != "" {
			if saveErr := auth.SaveConfigFile(configPath, cfg); saveErr != nil {
				logging.Warnf("could not persist the registered device identity: %v", saveErr)
			}
		}
	}
	return session, nil
}

func doLoginQRCode(client *api.Client, cfg *auth.Config, configPath string, timeout time.Duration) error {
	guest, err := ensureBootstrapGuest(client, cfg, configPath, "uulink-login")
	if err != nil {
		return fmt.Errorf("create guest: %w", err)
	}
	info, err := client.GenerateQRCodeLoginWithGuest(guest)
	if err != nil {
		return fmt.Errorf("generate QR code login: %w", err)
	}
	log.Printf("QR-code login URL: %s", info.QRCodeJumpURL)
	log.Printf("bootstrap credentials: token_len=%d status_query_ticket_len=%d",
		len(info.Token), len(info.StatusQueryTicket))

	deadline := time.Now().Add(timeout)
	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("QR code login timed out after %s", timeout)
		}
		status, err := client.QRCodeLoginStatusWithGuest(guest, info)
		if err != nil {
			var responseErr *api.ResponseError
			if errors.As(err, &responseErr) {
				return fmt.Errorf("QR code login status failed: %w", responseErr)
			}
			log.Printf("query QR code login status: %v", err)
			continue
		}
		log.Printf("QR code login status: login_status=%d token_len=%d qrcode_jump_url_len=%d keys=%v",
			status.LoginStatus, len(status.Token), len(status.QRCodeJumpURL), mapKeys(status.Raw))
		if status.LoginStatus == 4 {
			login, err := client.LoginByQRCodeWithGuest(guest, info)
			if err != nil {
				return fmt.Errorf("QR code login exchange failed: %w", err)
			}
			token := login.Token
			refreshedState, err := persistLogin(client, cfg, configPath, token)
			if err != nil {
				return err
			}
			log.Printf("QR code login confirmed; JWT length=%d user_id_len=%d config=%s",
				len(token), len(refreshedState.UserID), configPath)
			return nil
		}
		if status.Token != "" {
			log.Printf("QR code scanned; waiting for login exchange confirmation")
		}
		if status.LoginStatus != 0 {
			log.Printf("QR code scanned; waiting for login token")
		}
	}
}

func doGuestTest(client *api.Client) error {
	session, err := client.CreateGuest()
	if err != nil {
		return fmt.Errorf("create guest: %w", err)
	}
	log.Printf("guest session created: guest_id_len=%d token_len=%d user_id_len=%d device_id_len=%d",
		len(session.GuestID), len(session.Token), len(session.UserID), len(session.DeviceID))

	room, err := client.CreateGuestRoom(session)
	if err != nil {
		return fmt.Errorf("create guest room: %w", err)
	}
	log.Printf("guest room created: signaling=%s gateways=%d token_len=%d",
		room.SignalingServer, len(room.SignalingList), len(room.Token))
	log.Printf("guest room raw keys: %v", mapKeys(room.Raw))

	sig, err := signaling.Connect(&signaling.ConnectConfig{
		GatewayURL:  room.SignalingServer,
		NRDAuth:     room.Token,
		Controlling: false,
	})
	if err != nil {
		return fmt.Errorf("connect guest signaling: %w", err)
	}
	defer sig.Close()

	select {
	case <-sig.NamespaceConnected():
		log.Printf("guest signaling namespace connected")
	case <-time.After(5 * time.Second):
		log.Printf("guest signaling namespace connect timeout")
	case <-sig.Done():
		return fmt.Errorf("guest signaling closed before namespace connection")
	}

	time.Sleep(2 * time.Second)

	share, err := client.GetGuestShareInfo(session)
	if err != nil {
		return fmt.Errorf("get guest share info: %w", err)
	}
	log.Printf("guest share info: alias=%q connect_id=%q connect_code_len=%d",
		share.Alias, share.ConnectID, len(share.ConnectCode))
	log.Printf("guest share info raw keys: %v", mapKeys(share.Raw))

	if share.ConnectCode == "" {
		log.Printf("connect_code is empty; uploading generated share pass code")
		share, err = ensureGuestShareCode(client, session, share, guestShareOptions{AuthMode: api.ShareAuthTemporary})
		if err != nil {
			return fmt.Errorf("upload guest share sign: %w", err)
		}
		log.Printf("guest share info refreshed: alias=%q connect_id=%q connect_code_len=%d",
			share.Alias, share.ConnectID, len(share.ConnectCode))

	}

	if share.ConnectCode == "" {
		return fmt.Errorf("guest share code was not generated")
	}

	log.Printf("attempting join by share code as logged-in controller")
	joined, err := client.JoinRoomByShareCode(share.ConnectID, share.ConnectCode)
	if err != nil {
		log.Printf("join by share code as logged-in controller failed: %v", err)
	} else {
		log.Printf("joined guest share room as logged-in controller: signaling=%s gateways=%d token_len=%d",
			joined.SignalingServer, len(joined.SignalingList), len(joined.Token))
	}

	log.Printf("attempting join by share code as guest controller")
	guestJoined, err := client.JoinRoomByShareCodeWithGuest(session, share.ConnectID, share.ConnectCode)
	if err != nil {
		return fmt.Errorf("join by share code as guest controller: %w", err)
	}
	log.Printf("joined guest share room as guest controller: signaling=%s gateways=%d token_len=%d",
		guestJoined.SignalingServer, len(guestJoined.SignalingList), len(guestJoined.Token))
	return nil
}

func mapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func buildSecurityPolicy(cfg *auth.Config, allowLAN bool, allowedPortsFlag string) (tunnel.SecurityPolicy, error) {
	policy := tunnel.SecurityPolicy{
		AllowLAN: allowLAN || cfg.AllowLAN,
	}
	if allowedPortsFlag != "" {
		ports, err := tunnel.ParseAllowedPorts(allowedPortsFlag)
		if err != nil {
			return tunnel.SecurityPolicy{}, fmt.Errorf("parse -allowed-ports: %w", err)
		}
		policy.AllowedPorts = ports
	} else if cfg.AllowedPorts != nil {
		ports := make(map[int]bool, len(cfg.AllowedPorts))
		for _, p := range cfg.AllowedPorts {
			if p <= 0 || p > 65535 {
				return tunnel.SecurityPolicy{}, fmt.Errorf("config allowed_ports: invalid port %d", p)
			}
			ports[p] = true
		}
		policy.AllowedPorts = ports
	}
	return policy, nil
}

func logSecurityPolicy(policy tunnel.SecurityPolicy) {
	if policy.AllowLAN {
		logging.Warnf("security policy: LAN/WAN target access enabled (-allow-lan)")
	} else {
		logging.Infof("security policy: target restricted to trusted loopback services (localhost/127.0.0.1)")
	}
	if policy.AllowedPorts != nil {
		if len(policy.AllowedPorts) == 0 {
			logging.Warnf("security policy: allowed target ports whitelist is empty; all target ports are denied")
		} else {
			logging.Infof("security policy: allowed target ports whitelist: %s", formatAllowedPorts(policy.AllowedPorts))
		}
	}
}

func formatAllowedPorts(ports map[int]bool) string {
	if len(ports) == 0 {
		return ""
	}
	sorted := make([]int, 0, len(ports))
	for port := range ports {
		sorted = append(sorted, port)
	}
	sort.Ints(sorted)

	var out strings.Builder
	rangeStart := sorted[0]
	previous := sorted[0]
	flush := func(end int) {
		if out.Len() > 0 {
			out.WriteByte(',')
		}
		if rangeStart == end {
			fmt.Fprintf(&out, "%d", rangeStart)
			return
		}
		fmt.Fprintf(&out, "%d-%d", rangeStart, end)
	}
	for _, port := range sorted[1:] {
		if port != previous+1 {
			flush(previous)
			rangeStart = port
		}
		previous = port
	}
	flush(previous)
	return out.String()
}
