// uulink - standalone UU Remote client for port forwarding.
package main

import (
	"bufio"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/user/uulink/pkg/api"
	"github.com/user/uulink/pkg/auth"
	"github.com/user/uulink/pkg/logging"
	"github.com/user/uulink/pkg/peer"
	"github.com/user/uulink/pkg/signaling"
	"github.com/user/uulink/pkg/tunnel"
	"github.com/user/uulink/pkg/tunnel/mixsend"
)

func main() {
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
	forceRelay := flag.Bool("force-relay", false, "force WebRTC to use TURN relay only")
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
	customServe := flag.Bool("custom-serve", false, "run assistance server using custom verification code mode (unbound/no-login)")
	customConnect := flag.String("custom-connect", "", "connect ID of the remote assistance server to connect to using custom code")
	customCodeFlag := flag.String("custom-code", "", "custom verification code (8-16 alphanumeric characters) for server or client mode")
	flag.Parse()

	parsedLogLevel, err := logging.ParseLevel(*logLevel)
	if err != nil {
		log.Fatalf("parse log level: %v", err)
	}
	logging.SetLevel(parsedLogLevel)

	cfg, err := auth.LoadConfigFile(*configPath)
	if err != nil {
		if os.IsNotExist(err) && (*customServe || *unboundGuestServe || *customConnect != "") {
			cfg = &auth.Config{}
		} else {
			log.Fatalf("load config: %v", err)
		}
	}

	authMode, err := api.ParseShareAuthMode(*shareAuthMode)
	if err != nil {
		log.Fatalf("parse share auth mode: %v", err)
	}
	effectiveCustomCode := *customCodeFlag
	if effectiveCustomCode == "" {
		effectiveCustomCode = *guestCustomCode
	}
	if effectiveCustomCode == "" {
		effectiveCustomCode = cfg.CustomCode
	}
	if (effectiveCustomCode != "" || *customServe) && authMode == api.ShareAuthTemporary {
		authMode = api.ShareAuthCustom
	}
	if effectiveCustomCode != "" && authMode != api.ShareAuthTemporary {
		if err := api.ValidateCustomShareCode(effectiveCustomCode); err != nil {
			log.Fatalf("validate custom code: %v", err)
		}
	}

	secPolicy, err := buildSecurityPolicy(cfg, *allowLAN, *allowedPortsFlag)
	if err != nil {
		log.Fatalf("configure security policy: %v", err)
	}

	client := api.NewClient(cfg)

	if *refreshLogin {
		doRefreshLogin(client, cfg, *configPath, *loginQRCodeTimeout)
		return
	}
	if *listDevices {
		doListDevices(client)
		return
	}
	if *guestTest {
		doGuestTest(client)
		return
	}
	if *userInfo {
		doUserInfo(client)
		return
	}
	if *interactiveLogin {
		doInteractiveLogin(client, cfg, *configPath, *loginQRCodeTimeout, *loginCountryCode)
		return
	}
	if *loginMobile != "" {
		doMobileLogin(client, cfg, *configPath, *loginCountryCode, *loginMobile)
		return
	}
	if *loginQRCode {
		doLoginQRCode(client, cfg, *configPath, *loginQRCodeTimeout)
		return
	}
	if *shareControlMode {
		if *shareID == "" {
			log.Fatal("-share-id is required")
		}
		response, err := client.GetShareControlMode(*shareID)
		if err != nil {
			log.Fatalf("query share control mode: %v", err)
		}
		log.Printf("share control mode query complete: code=%v", response["code"])
		return
	}

	isCustomConnect := *customConnect != "" || (*shareJoin && effectiveCustomCode != "")
	targetShareID := *shareID
	if *customConnect != "" {
		targetShareID = *customConnect
	}
	if targetShareID == "" {
		targetShareID = cfg.ShareID
	}
	targetShareCode := *shareCode
	if targetShareCode == "" {
		targetShareCode = effectiveCustomCode
	}
	if targetShareCode == "" {
		targetShareCode = cfg.ShareCode
	}

	usesShareRoom := *shareJoin || *shareGuest || *shareConfirmation || isCustomConnect
	if usesShareRoom && targetShareID == "" {
		log.Fatal("share ID is required (use -custom-connect or -share-id)")
	}
	if usesShareRoom && !*shareConfirmation && targetShareCode == "" {
		log.Fatal("verification code is required (use -custom-code or -share-code)")
	}
	serverModesCount := 0
	if *serveMode { serverModesCount++ }
	if *guestServe { serverModesCount++ }
	if *unboundGuestServe { serverModesCount++ }
	if *customServe { serverModesCount++ }
	if serverModesCount > 1 {
		log.Fatal("only one server mode flag (-serve, -guest-serve, -unbound-guest-serve, -custom-serve) can be specified")
	}
	if *customServe {
		if effectiveCustomCode == "" {
			var err error
			effectiveCustomCode, err = api.GenerateCustomShareCode()
			if err != nil {
				log.Fatalf("generate custom code: %v", err)
			}
			logging.Infof("generated custom verification code: %s", effectiveCustomCode)
		}
		rules, err := configuredRules(cfg, *ruleIDFlag, *mappingFlag, *localHost, *localPort, *remoteHost, *remotePort)
		if err != nil {
			log.Fatalf("configure mappings: %v", err)
		}
		doUnboundGuestServe(client, cfg, rules, *roomFile, *forceRelay, guestShareOptions{
			ControlID:  *guestControlID,
			AuthMode:   api.ShareAuthCustom,
			CustomCode: effectiveCustomCode,
		}, secPolicy)
		return
	}
	if *unboundGuestServe {
		rules, err := configuredRules(cfg, *ruleIDFlag, *mappingFlag, *localHost, *localPort, *remoteHost, *remotePort)
		if err != nil {
			log.Fatalf("configure mappings: %v", err)
		}
		doUnboundGuestServe(client, cfg, rules, *roomFile, *forceRelay, guestShareOptions{
			ControlID:  *guestControlID,
			AuthMode:   authMode,
			CustomCode: effectiveCustomCode,
		}, secPolicy)
		return
	}
	if *guestServe {
		rules, err := configuredRules(cfg, *ruleIDFlag, *mappingFlag, *localHost, *localPort, *remoteHost, *remotePort)
		if err != nil {
			log.Fatalf("configure mappings: %v", err)
		}
		doGuestServe(client, cfg, rules, *roomFile, *forceRelay, guestShareOptions{
			ControlID:  *guestControlID,
			AuthMode:   authMode,
			CustomCode: effectiveCustomCode,
		}, secPolicy)
		return
	}
	if *serveMode {
		if *deviceID != "" {
			log.Fatal("-device cannot be combined with -serve; the server uses this config's device")
		}
		rules, err := configuredRules(cfg, *ruleIDFlag, *mappingFlag, *localHost, *localPort, *remoteHost, *remotePort)
		if err != nil {
			log.Fatalf("configure mappings: %v", err)
		}
		doServe(client, cfg, rules, *roomFile, *forceRelay, secPolicy)
		return
	}

	targetDevID := *deviceID
	if targetDevID == "" {
		targetDevID = cfg.DeviceID
	}

	if *roomFile == "" && !usesShareRoom && (targetDevID == "" || (targetDevID == cfg.DeviceID && !*allowSelf)) {
		log.Fatal("target device must differ from this machine (use -device)")
	}
	rules, err := configuredRules(cfg, *ruleIDFlag, *mappingFlag, *localHost, *localPort, *remoteHost, *remotePort)
	if err != nil {
		log.Fatalf("configure mappings: %v", err)
	}

	// Step 1: join the room created by the target device's server
	var room *api.RoomConnectionInfo
	controllerAppControlID := ""
	if *shareJoin || *shareConfirmation {
		logging.Infof("joining share room as controller")
	}
	switch {
	case *shareConfirmation:
		if *shareControlID == "" {
			_, controlModeErr := client.GetShareControlMode(*shareID)
			if controlModeErr != nil {
				logging.Debugf("share control mode query failed: %v", controlModeErr)
			}
		}
		controlID := *shareControlID
		if *shareControlID != "" {
			logging.Debugf("using explicit share control_id=%s", controlID)
		} else {
			var err error
			controlID, err = generateAppControlID()
			if err != nil {
				log.Fatalf("generate share control id: %v", err)
			}
			logging.Debugf("generated share control_id_length=%d", len(controlID))
		}
		controllerAppControlID = controlID
		room, err = client.JoinRoomByConfirmation(targetShareID, controlID)
		if err != nil {
			if responseErr, ok := err.(*api.ResponseError); ok {
				data, _ := responseErr.Response["data"].(map[string]any)
				logging.Debugf("join room by confirmation error data keys=%v", mapKeys(data))
			}
			log.Fatalf("join room by confirmation: %v", err)
		}
	case isCustomConnect:
		if err := api.ValidateCustomShareCode(targetShareCode); err != nil {
			log.Fatalf("validate custom code: %v", err)
		}
		logging.Infof("joining share room %s with custom verification code", targetShareID)
		guestSession, guestErr := client.CreateGuest()
		if guestErr != nil {
			log.Fatalf("create guest session: %v", guestErr)
		}
		room, err = client.JoinRoomByShareCodeWithGuest(guestSession, targetShareID, targetShareCode)
		if err != nil {
			if responseErr, ok := err.(*api.ResponseError); ok {
				data, _ := responseErr.Response["data"].(map[string]any)
				logging.Debugf("join room by custom code error data keys=%v", mapKeys(data))
			}
			log.Fatalf("join custom share room: %v", err)
		}
	case *shareJoin:
		room, err = client.JoinRoomByShareCode(targetShareID, targetShareCode)
		if err != nil {
			if responseErr, ok := err.(*api.ResponseError); ok {
				data, _ := responseErr.Response["data"].(map[string]any)
				logging.Debugf("join room by share code error data keys=%v", mapKeys(data))
			}
			log.Fatalf("join share room: %v", err)
		}
	case *shareGuest:
		guestSession, guestErr := client.CreateGuest()
		if guestErr != nil {
			log.Fatalf("create guest: %v", guestErr)
		}
		room, err = client.JoinRoomByShareCodeWithGuest(guestSession, targetShareID, targetShareCode)
		if err != nil {
			log.Fatalf("join guest share room: %v", err)
		}
	case *roomFile != "":
		room, err = loadRoomFile(*roomFile)
		if err != nil {
			log.Fatalf("load room file: %v", err)
		}
		logging.Debugf("loaded room from %s", *roomFile)
		// The room-file controller reuses the guest's signaling token. The
		// passive peer skips the controller-role events that the gateway
		// rejects for this token, while Controlling=true prevents the gateway
		// from treating the second connection as a duplicate controlled session.
		room.IsRoomFileController = true
	default:
		logging.Infof("joining remote device %s", targetDevID)
		room, err = client.JoinRoomByDevice(targetDevID, false)
		if err != nil {
			log.Fatalf("join room: %v", err)
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
		log.Fatalf("signaling connect: %v", err)
	}
	defer sig.Close()

	// Wait for namespace confirmation
	select {
	case <-sig.NamespaceConnected():
	case <-time.After(5 * time.Second):
		logging.Warnf("signaling namespace connect timeout")
	case <-sig.Done():
		log.Fatal("signaling closed")
	}

	// Log forward_setting events (server pushes these after answer)
	sig.On("forward_setting", func(ev *signaling.Event) {
		if len(ev.Args) > 0 {
			logging.Debugf("[signaling] forward_setting received (%d bytes)", len(ev.Args[0]))
		}
	})

	if *capFlag != "" {
		if err := peer.CapOverride(*capFlag); err != nil {
			log.Fatalf("cap override: %v", err)
		}
		logging.Debugf("capability blob overridden: %s", *capFlag)
	}
	var debugRule tunnel.Rule
	var ruleID string
	if len(rules) > 0 {
		debugRule = rules[0]
		ruleID = debugRule.ID
	}
	if (*pckSweep || *mixkcpMode) && len(rules) == 0 {
		log.Fatal("-pck-sweep and -mixkcp require at least one port mapping")
	}

	// Step 4: control handshake (gets client_id, ice_id, TURN servers)
	var tun *tunnel.Tunnel
	peerDeviceID := cfg.DeviceID
	if *controlDeviceID != "" {
		peerDeviceID = *controlDeviceID
		logging.Debugf("control ConnectOptions device_id=%s auth_device_id=%s", peerDeviceID, cfg.DeviceID)
	}
	p, err := peer.NewController(&peer.Config{
		Signal:       sig,
		DeviceID:     peerDeviceID,
		AppControlID: controllerAppControlID,
		Passive:      room.IsRoomFileController,
		ForceRelay:   *forceRelay,
		OnSignalData: func(data []byte) {
			if tun != nil {
				tun.HandleMessage(data)
			}
		}})
	if err != nil {
		log.Fatalf("control handshake: %v", err)
	}
	defer p.Close()

	// Step 5: create PeerConnection + data channels + send soac offer
	if err := p.Connect(nil); err != nil {
		log.Fatalf("peer connect: %v", err)
	}

	// Step 6: start the local listener once the PM data channel is ready.
	tun = tunnel.NewTunnelWithRules(rules, &peerSender{peer: p, sig: sig})
	tun.SetSecurityPolicy(secPolicy)
	p.OnFileChannelOpen(func() {
		if len(rules) > 0 {
			if err := tun.Start(); err != nil {
				log.Fatalf("start tunnel: %v", err)
			}
			logActiveMappings("port forwarding active", rules)
		} else {
			logging.Infof("inbound port mapping active (no local listeners configured)")
		}
		logSecurityPolicy(secPolicy)
	})
	defer tun.Stop()

	// PCK sweep mode: replicate the official channel setup then try CONNECT
	// on each PCK logical channel to find where PM frames are accepted.
	if *pckSweep {
		readyCh := make(chan struct{})
		var once sync.Once
		p.OnBinaryChannelOpen(func() {
			once.Do(func() { close(readyCh) })
		})
		go func() {
			<-readyCh
			time.Sleep(500 * time.Millisecond)
			logging.Debugf("[pck] replicating channel setup")
			// session setup kinds 1,2 then register chans 3,4 like the official client
			if err := p.SendSignalPB(tunnel.BuildSessionSetup(1)); err != nil {
				logging.Errorf("[pck] setup1 error: %v", err)
			}
			if err := p.SendSignalPB(tunnel.BuildSessionSetup(2)); err != nil {
				logging.Errorf("[pck] setup2 error: %v", err)
			}
			time.Sleep(300 * time.Millisecond)
			for _, ch := range []uint32{3, 4} {
				if err := p.SendSignalPB(tunnel.BuildRegistration(ch)); err != nil {
					logging.Errorf("[pck] reg %d error: %v", ch, err)
				}
				time.Sleep(200 * time.Millisecond)
			}
			// now sweep CONNECT across target channels
			for targetChan := uint32(0); targetChan <= 20; targetChan++ {
				frame, err := tunnel.BuildConnectPCK(targetChan, ruleID, "1", debugRule.TargetHost, debugRule.TargetPort)
				if err != nil {
					logging.Errorf("[pck] build CONNECT error: %v", err)
					continue
				}
				if err := p.SendSignalPB(frame); err != nil {
					logging.Errorf("[pck] target chan %d send error: %v", targetChan, err)
					continue
				}
				logging.Debugf("[pck] CONNECT sent on target chan %d", targetChan)
				time.Sleep(2 * time.Second)
			}
			logging.Debugf("[pck] sweep done")
		}()
	}

	logging.Infof("waiting for WebRTC connection")

	if *mixkcpMode {
		p.OnICEConnected(func() {
			peerAddr := firstHostCandidate(p.RemoteCandidates())
			if peerAddr == nil {
				logging.Errorf("[mixkcp] no host candidate from remote, cannot send")
				return
			}
			sender, err := mixsend.NewSender(peerAddr)
			if err != nil {
				logging.Errorf("[mixkcp] sender: %v", err)
				return
			}
			defer sender.Close()
			logging.Debugf("[mixkcp] sending CONNECT to %s (rule %s, target %s:%d)",
				peerAddr, ruleID, debugRule.TargetHost, debugRule.TargetPort)

			// CONNECT payload: the PM JSON message (wire format per findings 9.8;
			// the official client's crypto layer is not reproduced — this sends the
			// correctly structured frame with the JSON body in the payload region).
			connectJSON := fmt.Sprintf(`{"seq":"6","timestamp":"%d","portMappingFrame":{"sessionId":"1","ruleId":"%s","streamId":"1","payload":"%s"}}`,
				time.Now().Unix(), ruleID, base64.StdEncoding.EncodeToString(
					[]byte(fmt.Sprintf(`{"version":1,"target_port":%d,"target_host":"%s"}`, debugRule.TargetPort, debugRule.TargetHost))))
			if err := sender.SendPMFrame(0x43, []byte(connectJSON)); err != nil {
				logging.Errorf("[mixkcp] send CONNECT: %v", err)
				return
			}
			logging.Debugf("[mixkcp] CONNECT frame sent (%d bytes)", len(connectJSON))

			// wait for a possible SYN_ACK (honest no-response state recorded)
			senderDeadline := time.Now().Add(10 * time.Second)
			for time.Now().Before(senderDeadline) {
				sender.SetReadDeadline(senderDeadline)
				f, err := sender.ReceivePMFrame()
				if err != nil {
					logging.Debugf("[mixkcp] no SYN_ACK received within deadline: %v", err)
					return
				}
				logging.Debugf("[mixkcp] inbound frame cmd=%#x", f.Cmd)
				if f.Cmd == 0x5d {
					logging.Debugf("[mixkcp] SYN_ACK-like frame received")
				}
			}
		})
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

	select {
	case <-interrupt:
		logging.Infof("interrupted, shutting down")
	case <-sig.Done():
		logging.Infof("signaling connection closed, shutting down")
	}
}

func doServe(client *api.Client, cfg *auth.Config, rules []tunnel.Rule, roomFile string, forceRelay bool, policy tunnel.SecurityPolicy) {
	hostname, err := cfg.EffectiveHostname()
	if err != nil {
		log.Fatalf("resolve hostname: %v", err)
	}
	logging.Debugf("registering controlled device %q", hostname)
	if _, err := client.InitMacDevice(hostname); err != nil {
		log.Fatalf("register controlled device: %v", err)
	}
	if _, err := client.SetMacControllable(true); err != nil {
		log.Fatalf("enable controlled device: %v", err)
	}

	logging.Debugf("creating controlled room")
	room, err := client.CreateRoom()
	if err != nil {
		log.Fatalf("create room: %v", err)
	}
	serveRoom(client, cfg, rules, room, roomFile, nil, forceRelay, guestShareOptions{}, policy)
}

type guestShareOptions struct {
	ControlID  string
	AuthMode   api.ShareAuthMode
	CustomCode string
}

func doGuestServe(client *api.Client, cfg *auth.Config, rules []tunnel.Rule, roomFile string, forceRelay bool, shareOptions guestShareOptions, policy tunnel.SecurityPolicy) {
	session, err := client.CreateGuest()
	if err != nil {
		log.Fatalf("create guest: %v", err)
	}
	room, err := client.CreateGuestRoom(session)
	if err != nil {
		log.Fatalf("create guest room: %v", err)
	}
	serveRoom(client, cfg, rules, room, roomFile, session, forceRelay, shareOptions, policy)
}

func doUnboundGuestServe(client *api.Client, cfg *auth.Config, rules []tunnel.Rule, roomFile string, forceRelay bool, shareOptions guestShareOptions, policy tunnel.SecurityPolicy) {
	hostname, err := cfg.EffectiveHostname()
	if err != nil {
		log.Fatalf("resolve hostname: %v", err)
	}
	session, identity, err := client.CreateUnboundGuest(hostname)
	if err != nil {
		log.Fatalf("create unbound guest: %v", err)
	}
	cfg.ClientID = identity.ClientID
	cfg.DeviceID = identity.DeviceID
	cfg.Platform = 1
	logging.Debugf("unbound guest identity created")

	room, err := client.CreateGuestRoom(session)
	if err != nil {
		log.Fatalf("create guest room: %v", err)
	}
	serveRoom(client, cfg, rules, room, roomFile, session, forceRelay, shareOptions, policy)
}

func serveRoom(client *api.Client, cfg *auth.Config, rules []tunnel.Rule, room *api.RoomConnectionInfo, roomFile string, guestSession *api.GuestSession, forceRelay bool, shareOptions guestShareOptions, policy tunnel.SecurityPolicy) {
	if roomFile != "" {
		roomInfoFile := roomFile
		if guestSession != nil {
			roomInfoFile = roomFile + ".room"
		}
		if err := saveRoomFile(roomInfoFile, room); err != nil {
			log.Fatalf("save room file: %v", err)
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
		log.Fatalf("signaling connect: %v", err)
	}
	defer sig.Close()

	select {
	case <-sig.NamespaceConnected():
	case <-time.After(5 * time.Second):
		log.Fatal("signaling namespace connect timeout")
	case <-sig.Done():
		log.Fatal("signaling closed")
	}

	var share *api.GuestShareInfo
	if guestSession != nil {
		if _, err := client.GuestSetDeviceControllable(guestSession, true); err != nil {
			log.Fatalf("set guest device controllable: %v", err)
		}
		share, err = waitForGuestConnectID(client, guestSession)
		if err != nil {
			log.Fatalf("get guest share info: %v", err)
		}
		share, err = ensureGuestShareCode(client, guestSession, share, shareOptions)
		if err != nil {
			log.Fatalf("prepare guest share code: %v", err)
		}
		controlModeID := shareOptions.ControlID
		if controlModeID == "" {
			controlModeID = share.ConnectID
		}
		if _, err := client.GuestShareUploadControlMode(guestSession,
			api.NewGuestShareUploadControlModeRequest(controlModeID, true, shareOptions.AuthMode)); err != nil {
			log.Fatalf("upload guest control mode: %v", err)
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
				log.Fatalf("save guest share file: %v", err)
			}
			logging.Debugf("saved guest share info to %s", roomFile)
		}
		if shareOptions.AuthMode == api.ShareAuthCustom {
			logging.Infof("custom assistance ready: connect_id=%s custom_code=%s", share.ConnectID, share.ConnectCode)
			logging.Infof("client connect command: ./uulink -custom-connect %s -custom-code %s", share.ConnectID, share.ConnectCode)
		} else {
			logging.Infof("guest share ready: connect_id=%s connect_code=%s", share.ConnectID, share.ConnectCode)
		}
	}

	var tun *tunnel.Tunnel
	p, err := peer.NewControlled(&peer.Config{
		Signal: sig,
		OnSignalData: func(data []byte) {
			if tun != nil {
				tun.HandleMessage(data)
			}
		},
	})
	if err != nil {
		log.Fatalf("create controlled peer: %v", err)
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

	tun = tunnel.NewTunnelWithRules(rules, &peerSender{peer: p, sig: sig})
	tun.SetSecurityPolicy(policy)
	p.OnFileChannelOpen(func() {
		if len(rules) > 0 {
			if err := tun.Start(); err != nil {
				log.Fatalf("start tunnel: %v", err)
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
	select {
	case <-interrupt:
		logging.Infof("interrupted, shutting down")
	case <-sig.Done():
		logging.Infof("signaling connection closed, shutting down")
	}
}

func waitForGuestConnectID(client *api.Client, session *api.GuestSession) (*api.GuestShareInfo, error) {
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
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
	sig  *signaling.Client
}

func (s *peerSender) SendFrame(msg []byte) error {
	// PM protobuf messages are sent directly on FILE_DATA_CHANNEL.
	return s.peer.SendSignalPB(msg)
}

func loadConfig(path string) (*auth.Config, error) {
	return auth.LoadConfigFile(path)
}

func doListDevices(client *api.Client) {
	resp, err := client.GetDeviceList()
	if err != nil {
		log.Fatalf("get device list: %v", err)
	}

	data, _ := resp["data"].(map[string]any)
	if data == nil {
		log.Fatalf("unexpected response format: %v", resp)
	}

	fmt.Printf("%-24s %-16s %-14s %-8s %-12s %s\n", "DEVICE_ID", "NAME", "STATUS", "PLAT", "CLIENT_ID", "VERSION")
	fmt.Printf("%-24s %-16s %-14s %-8s %-12s %s\n", "--------", "----", "------", "----", "---------", "-------")

	lists := []string{"current_device", "my_binded_devices", "others_shared_devices"}
	for _, listName := range lists {
		var items []any
		if v, ok := data[listName].([]any); ok {
			items = v
		} else if v, ok := data[listName].(map[string]any); ok {
			items = []any{v}
		}
		for _, item := range items {
			dev, ok := item.(map[string]any)
			if !ok {
				continue
			}
			plat := ""
			if v, ok := dev["platform"].(float64); ok {
				plat = fmt.Sprintf("%.0f", v)
			}
			fmt.Printf("%-24s %-16s %-14s %-8s %-12s %s\n",
				strval(dev, "device_id"), strval(dev, "alias"),
				strval(dev, "status"), plat, strval(dev, "client_id"), strval(dev, "version_name"))
		}
	}
}

func doUserInfo(client *api.Client) {
	resp, err := client.GetUserInfo()
	if err != nil {
		log.Fatalf("get user info: %v", err)
	}
	data, _ := resp["data"].(map[string]any)
	if data == nil {
		log.Fatalf("unexpected user info response: %v", resp)
	}
	code, _ := resp["code"].(float64)
	message, _ := resp["msg"].(string)
	nickname, _ := data["nickname"].(string)
	userID, _ := data["user_id"].(string)
	log.Printf("user info: code=%v msg=%q nickname=%q user_id_len=%d keys=%v",
		code, message, nickname, len(userID), mapKeys(data))
}

type qrCodeLoginFileInfo struct {
	GuestID           string `json:"guest_id"`
	GuestToken        string `json:"guest_token"`
	QRCodeJumpURL     string `json:"qrcode_jump_url"`
	Token             string `json:"token"`
	StatusQueryTicket string `json:"status_query_ticket"`
}

func saveQRCodeLoginInfo(path string, session *api.GuestSession, info *api.QRCodeLoginInfo) error {
	data, err := json.Marshal(qrCodeLoginFileInfo{
		GuestID:           session.GuestID,
		GuestToken:        session.Token,
		QRCodeJumpURL:     info.QRCodeJumpURL,
		Token:             info.Token,
		StatusQueryTicket: info.StatusQueryTicket,
	})
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func saveQRCodeLoginStatus(path string, status *api.QRCodeLoginStatusResult) error {
	data, err := json.MarshalIndent(status.Raw, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func doInteractiveLogin(client *api.Client, cfg *auth.Config, configPath string, qrTimeout time.Duration, defaultCountryCode string) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Select login method:")
	fmt.Println("  1. QR code scan (Recommended)")
	fmt.Println("  2. SMS verification code (Mobile)")
	fmt.Print("Enter choice [1/2, default 1]: ")
	choiceText, _ := reader.ReadString('\n')
	choice := strings.TrimSpace(choiceText)
	switch choice {
	case "2", "mobile", "sms":
		doMobileLogin(client, cfg, configPath, defaultCountryCode, "")
	default:
		doLoginQRCode(client, cfg, configPath, qrTimeout)
	}
}

func doMobileLogin(client *api.Client, cfg *auth.Config, configPath, countryCode, mobile string) {
	reader := bufio.NewReader(os.Stdin)
	if mobile == "" {
		fmt.Print("Enter mobile phone number: ")
		text, err := reader.ReadString('\n')
		if err != nil {
			log.Fatalf("read mobile number: %v", err)
		}
		mobile = strings.TrimSpace(text)
		if mobile == "" {
			log.Fatal("mobile phone number cannot be empty")
		}
	}
	if countryCode == "" {
		countryCode = "+86"
	}

	log.Printf("requesting SMS verification code for %s %s...", countryCode, mobile)
	resp, err := client.RequestMobileCode(countryCode, mobile)
	if err != nil {
		if respErr, ok := err.(*api.ResponseError); ok {
			log.Fatalf("request SMS code failed: code=%d msg=%q (note: server may require captcha if triggered by security policy)",
				respErr.Code, respErr.Message)
		}
		log.Fatalf("request SMS code: %v", err)
	}
	log.Printf("SMS code request sent (code=%v msg=%q)", resp["code"], resp["msg"])

	fmt.Print("Enter SMS verification code: ")
	codeText, err := reader.ReadString('\n')
	if err != nil {
		log.Fatalf("read SMS code: %v", err)
	}
	code := strings.TrimSpace(codeText)
	if code == "" {
		log.Fatal("verification code cannot be empty")
	}

	login, err := client.LoginByMobile(countryCode, mobile, code)
	if err != nil {
		if respErr, ok := err.(*api.ResponseError); ok {
			log.Fatalf("mobile login failed: code=%d msg=%q", respErr.Code, respErr.Message)
		}
		log.Fatalf("mobile login: %v", err)
	}

	data, _ := login["data"].(map[string]any)
	token, _ := data["token"].(string)
	if token == "" {
		log.Fatalf("mobile login response has no token: %v", login)
	}

	userID, err := api.JWTSubject(token)
	if err != nil {
		log.Fatalf("decode login JWT: %v", err)
	}
	cfg.JWT = token
	cfg.UserID = userID
	cfg.GuestID = ""
	if err := auth.SaveConfigFile(configPath, cfg); err != nil {
		log.Fatalf("save refreshed config: %v", err)
	}
	refreshedState, err := client.GetLoginState()
	if err != nil {
		log.Fatalf("validate refreshed login state: %v", err)
	}
	if !refreshedState.Valid {
		log.Fatalf("refreshed login state is invalid")
	}
	log.Printf("mobile login confirmed; JWT length=%d user_id_len=%d config=%s",
		len(token), len(refreshedState.UserID), configPath)
}

func doRefreshLogin(client *api.Client, cfg *auth.Config, configPath string, timeout time.Duration) {
	state, err := client.GetLoginState()
	if err == nil && state.Valid {
		log.Printf("login state valid; no refresh needed (user_id_len=%d nickname=%q)",
			len(state.UserID), state.Nickname)
		return
	}
	if err != nil {
		var responseErr *api.ResponseError
		if !errors.As(err, &responseErr) {
			log.Fatalf("validate login state: %v", err)
		}
		log.Printf("login state invalid: %v", responseErr)
	} else {
		log.Printf("login state invalid: user info response has no user_id")
	}
	doLoginQRCode(client, cfg, configPath, timeout)
}

func doLoginQRCode(client *api.Client, cfg *auth.Config, configPath string, timeout time.Duration) {
	guest, err := client.CreateGuest()
	if err != nil {
		log.Fatalf("create guest: %v", err)
	}
	info, err := client.GenerateQRCodeLoginWithGuest(guest)
	if err != nil {
		log.Fatalf("generate QR code login: %v", err)
	}
	if err := saveQRCodeLoginInfo("workspace/login-qrcode.json", guest, info); err != nil {
		log.Fatalf("save QR code login info: %v", err)
	}
	log.Printf("QR-code login URL: %s", info.QRCodeJumpURL)
	log.Printf("bootstrap credentials: token_len=%d status_query_ticket_len=%d",
		len(info.Token), len(info.StatusQueryTicket))
	log.Printf("saved QR code login info to workspace/login-qrcode.json")

	deadline := time.Now().Add(timeout)
	for {
		if time.Now().After(deadline) {
			log.Fatalf("QR code login timed out after %s", timeout)
		}
		status, err := client.QRCodeLoginStatusWithGuest(guest, info)
		if err != nil {
			var responseErr *api.ResponseError
			if errors.As(err, &responseErr) {
				log.Fatalf("QR code login status failed: %v", responseErr)
			}
			log.Printf("query QR code login status: %v", err)
			continue
		}
		if err := saveQRCodeLoginStatus("workspace/login-qrcode-status.json", status); err != nil {
			log.Fatalf("save QR code login status: %v", err)
		}
		log.Printf("QR code login status: login_status=%d token_len=%d qrcode_jump_url_len=%d keys=%v",
			status.LoginStatus, len(status.Token), len(status.QRCodeJumpURL), mapKeys(status.Raw))
		if status.LoginStatus == 4 {
			login, err := client.LoginByQRCodeWithGuest(guest, info)
			if err != nil {
				log.Fatalf("QR code login exchange failed: %v", err)
			}
			data, _ := login["data"].(map[string]any)
			token, _ := data["token"].(string)
			if token == "" {
				log.Fatalf("QR code login exchange response has no token: %v", login)
			}
			if err := os.WriteFile("workspace/login-qrcode-jwt.json", []byte(token), 0600); err != nil {
				log.Fatalf("save QR code login JWT: %v", err)
			}
			userID, err := api.JWTSubject(token)
			if err != nil {
				log.Fatalf("decode QR code login JWT: %v", err)
			}
			cfg.JWT = token
			cfg.UserID = userID
			cfg.GuestID = ""
			if err := auth.SaveConfigFile(configPath, cfg); err != nil {
				log.Fatalf("save refreshed config: %v", err)
			}
			refreshedState, err := client.GetLoginState()
			if err != nil {
				log.Fatalf("validate refreshed login state: %v", err)
			}
			if !refreshedState.Valid {
				log.Fatalf("refreshed login state is invalid")
			}
			log.Printf("QR code login confirmed; JWT length=%d user_id_len=%d config=%s",
				len(token), len(refreshedState.UserID), configPath)
			return
		}
		if status.Token != "" {
			log.Printf("QR code login confirmed; raw response saved to workspace/login-qrcode-status.json")
			return
		}
		if status.LoginStatus != 0 {
			log.Printf("QR code scanned; waiting for login token")
		}
	}
}

func doGuestTest(client *api.Client) {
	session, err := client.CreateGuest()
	if err != nil {
		log.Fatalf("create guest: %v", err)
	}
	log.Printf("guest session created: guest_id_len=%d token_len=%d user_id_len=%d device_id_len=%d",
		len(session.GuestID), len(session.Token), len(session.UserID), len(session.DeviceID))

	room, err := client.CreateGuestRoom(session)
	if err != nil {
		log.Fatalf("create guest room: %v", err)
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
		log.Fatalf("connect guest signaling: %v", err)
	}
	defer sig.Close()

	select {
	case <-sig.NamespaceConnected():
		log.Printf("guest signaling namespace connected")
	case <-time.After(5 * time.Second):
		log.Printf("guest signaling namespace connect timeout")
	case <-sig.Done():
		log.Fatalf("guest signaling closed before namespace connect")
	}

	time.Sleep(2 * time.Second)

	share, err := client.GetGuestShareInfo(session)
	if err != nil {
		log.Fatalf("get guest share info: %v", err)
	}
	log.Printf("guest share info: alias=%q connect_id=%q connect_code_len=%d",
		share.Alias, share.ConnectID, len(share.ConnectCode))
	log.Printf("guest share info raw keys: %v", mapKeys(share.Raw))

	if share.ConnectCode == "" {
		log.Printf("connect_code is empty; uploading generated share pass code")
		share, err = ensureGuestShareCode(client, session, share, guestShareOptions{AuthMode: api.ShareAuthTemporary})
		if err != nil {
			log.Fatalf("upload guest share sign: %v", err)
		}
		log.Printf("guest share info refreshed: alias=%q connect_id=%q connect_code_len=%d",
			share.Alias, share.ConnectID, len(share.ConnectCode))

	}

	if share.ConnectCode == "" {
		log.Fatal("guest share code was not generated")
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
		log.Printf("join by share code as guest controller failed: %v", err)
		return
	}
	log.Printf("joined guest share room as guest controller: signaling=%s gateways=%d token_len=%d",
		guestJoined.SignalingServer, len(guestJoined.SignalingList), len(guestJoined.Token))
}

func mapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func strval(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func hexPreview(data []byte, n int) string {
	if len(data) > n {
		data = data[:n]
	}
	hex := make([]byte, 0, len(data)*2)
	for _, b := range data {
		hex = append(hex, "0123456789abcdef"[b>>4], "0123456789abcdef"[b&0xf])
	}
	return string(hex)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// firstHostCandidate extracts a UDP host candidate address from the remote
// ICE candidates (preferring LAN addresses like the official client's fd85
// path to 10.10.10.13).
func firstHostCandidate(cands []string) *net.UDPAddr {
	for _, c := range cands {
		if !strings.Contains(c, " typ host") {
			continue
		}
		if strings.Contains(c, " tcp ") {
			continue // mix-kcp rides the UDP path
		}
		// candidate:<foundation> <component> <transport> <priority> <ip> <port> typ host ...
		parts := strings.Fields(c)
		if len(parts) < 6 {
			continue
		}
		ip := parts[4]
		port := parts[5]
		addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(ip, port))
		if err == nil {
			return addr
		}
	}
	return nil
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
