// uulink - standalone UU Remote client for port forwarding.
package main

import (
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
	roomFile := flag.String("room-file", "", "share room connection or guest share info through a file (same-host debug E2E)")
	listDevices := flag.Bool("list", false, "list available devices and exit")
	guestTest := flag.Bool("guest", false, "run guest identity/share smoke test and exit")
	userInfo := flag.Bool("user-info", false, "show current user info and exit")
	loginQRCode := flag.Bool("login-qrcode", false, "exchange an official QR-code login for a JWT and update the config")
	refreshLogin := flag.Bool("refresh-login", false, "validate the current JWT and refresh it by QR-code login only if needed")
	loginQRCodeTimeout := flag.Duration("login-qrcode-timeout", 5*time.Minute, "maximum time to wait for QR-code login confirmation")
	shareJoin := flag.Bool("share", false, "join a remote-assistance share by ID and code")
	shareGuest := flag.Bool("share-guest", false, "join a remote-assistance share using a guest identity")
	shareID := flag.String("share-id", "", "remote-assistance connect ID")
	shareCode := flag.String("share-code", "", "remote-assistance verification code")
	ruleIDFlag := flag.String("rule-id", "", "registered rule ID on the remote device (must match)")
	capFlag := flag.String("cap", "", "override ConnectOptions capability blob (hex, e.g. 08061002180120023002380240024801)")
	pckSweep := flag.Bool("pck-sweep", false, "sweep PCK.V3 channels with CONNECT frames after setup")
	mixkcpMode := flag.Bool("mixkcp", false, "send PM frames over mix-kcp UDP to the ICE peer (raw frame format, crypto layout preserved)")
	localPort := flag.Int("local", 0, "local port to listen on")
	localHost := flag.String("local-host", "127.0.0.1", "local address to listen on")
	remoteHost := flag.String("remote-host", "127.0.0.1", "remote target host")
	remotePort := flag.Int("remote-port", 0, "remote target port")
	flag.Parse()

	cfg, err := auth.LoadConfigFile(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
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
	if *loginQRCode {
		doLoginQRCode(client, cfg, *configPath, *loginQRCodeTimeout)
		return
	}

	usesShareRoom := *shareJoin || *shareGuest
	if usesShareRoom && (*shareID == "" || *shareCode == "") {
		log.Fatal("both -share-id and -share-code are required")
	}
	if *serveMode && *guestServe {
		log.Fatal("-serve and -guest-serve cannot be combined")
	}
	if *guestServe {
		rules, err := configuredRules(cfg, *ruleIDFlag, *localHost, *localPort, *remoteHost, *remotePort)
		if err != nil {
			log.Fatalf("configure mappings: %v", err)
		}
		doGuestServe(client, cfg, rules, *roomFile)
		return
	}
	if *serveMode {
		if *deviceID != "" {
			log.Fatal("-device cannot be combined with -serve; the server uses this config's device")
		}
		rules, err := configuredRules(cfg, *ruleIDFlag, *localHost, *localPort, *remoteHost, *remotePort)
		if err != nil {
			log.Fatalf("configure mappings: %v", err)
		}
		doServe(client, cfg, rules, *roomFile)
		return
	}

	targetDevID := *deviceID
	if targetDevID == "" {
		targetDevID = cfg.DeviceID
	}

	if *roomFile == "" && !usesShareRoom && (targetDevID == "" || (targetDevID == cfg.DeviceID && !*allowSelf)) {
		log.Fatal("target device must differ from this machine (use -device)")
	}
	rules, err := configuredRules(cfg, *ruleIDFlag, *localHost, *localPort, *remoteHost, *remotePort)
	if err != nil {
		log.Fatalf("configure mappings: %v", err)
	}

	// Step 1: join the room created by the target device's server
	var room *api.RoomConnectionInfo
	switch {
	case *shareJoin:
		log.Println("joining room by share code...")
		room, err = client.JoinRoomByShareCode(*shareID, *shareCode)
		if err != nil {
			log.Fatalf("join share room: %v", err)
		}
	case *shareGuest:
		log.Println("joining room by share code with a guest identity...")
		guestSession, guestErr := client.CreateGuest()
		if guestErr != nil {
			log.Fatalf("create guest: %v", guestErr)
		}
		room, err = client.JoinRoomByShareCodeWithGuest(guestSession, *shareID, *shareCode)
		if err != nil {
			log.Fatalf("join guest share room: %v", err)
		}
	case *roomFile != "":
		room, err = loadRoomFile(*roomFile)
		if err != nil {
			log.Fatalf("load room file: %v", err)
		}
		log.Printf("loaded room from %s", *roomFile)
	default:
		log.Printf("joining room for device %s...", targetDevID)
		room, err = client.JoinRoomByDevice(targetDevID, false)
		if err != nil {
			log.Fatalf("join room: %v", err)
		}
	}
	log.Printf("signaling_server=%s (%d gateways)", room.SignalingServer, len(room.SignalingList))

	gateway := room.SignalingServer
	if gateway == "" && len(room.SignalingList) > 0 {
		gateway = room.SignalingList[0]
	}

	// Step 2: connect to signaling gateway
	log.Printf("connecting to signaling gateway %s...", gateway)
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
		log.Println("warning: namespace connect timeout")
	case <-sig.Done():
		log.Fatal("signaling closed")
	}

	// Log forward_setting events (server pushes these after answer)
	sig.On("forward_setting", func(ev *signaling.Event) {
		if len(ev.Args) > 0 {
			log.Printf("[signaling] forward_setting: %s", string(ev.Args[0])[:min(400, len(string(ev.Args[0])))])
		}
	})

	if *capFlag != "" {
		if err := peer.CapOverride(*capFlag); err != nil {
			log.Fatalf("cap override: %v", err)
		}
		log.Printf("capability blob overridden: %s", *capFlag)
	}
	debugRule := rules[0]
	ruleID := debugRule.ID

	// Step 4: control handshake (gets client_id, ice_id, TURN servers)
	log.Println("sending control event...")
	var tun *tunnel.Tunnel
	peerDeviceID := cfg.DeviceID
	if *controlDeviceID != "" {
		peerDeviceID = *controlDeviceID
		log.Printf("control ConnectOptions device_id=%s (auth device_id=%s)", peerDeviceID, cfg.DeviceID)
	}
	p, err := peer.NewController(&peer.Config{
		Signal:   sig,
		DeviceID: peerDeviceID,
		OnSignalData: func(data []byte) {
			// Port mapping frames arrive on the room's pb channel
			log.Printf("[pb-recv] %s", truncateStr(string(data), 200))
			if tun != nil {
				tun.HandleMessage(data)
			}
		}})
	if err != nil {
		log.Fatalf("control handshake: %v", err)
	}
	defer p.Close()

	// Step 5: create PeerConnection + data channels + send soac offer
	log.Println("creating WebRTC offer...")
	if err := p.Connect(nil); err != nil {
		log.Fatalf("peer connect: %v", err)
	}

	// Step 6: start the local listener once the PM data channel is ready.
	tun = tunnel.NewTunnelWithRules(rules, &peerSender{peer: p, sig: sig})
	p.OnFileChannelOpen(func() {
		if err := tun.Start(); err != nil {
			log.Fatalf("start tunnel: %v", err)
		}
		logActiveMappings("port forwarding active", rules)
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
			log.Println("[pck] replicating channel setup")
			// session setup kinds 1,2 then register chans 3,4 like the official client
			if err := p.SendSignalPB(tunnel.BuildSessionSetup(1)); err != nil {
				log.Printf("[pck] setup1 error: %v", err)
			}
			if err := p.SendSignalPB(tunnel.BuildSessionSetup(2)); err != nil {
				log.Printf("[pck] setup2 error: %v", err)
			}
			time.Sleep(300 * time.Millisecond)
			for _, ch := range []uint32{3, 4} {
				if err := p.SendSignalPB(tunnel.BuildRegistration(ch)); err != nil {
					log.Printf("[pck] reg %d error: %v", ch, err)
				}
				time.Sleep(200 * time.Millisecond)
			}
			// now sweep CONNECT across target channels
			for targetChan := uint32(0); targetChan <= 20; targetChan++ {
				frame, err := tunnel.BuildConnectPCK(targetChan, ruleID, "1", debugRule.TargetHost, debugRule.TargetPort)
				if err != nil {
					log.Printf("[pck] build CONNECT error: %v", err)
					continue
				}
				if err := p.SendSignalPB(frame); err != nil {
					log.Printf("[pck] target chan %d send error: %v", targetChan, err)
					continue
				}
				log.Printf("[pck] CONNECT sent on target chan %d, waiting 2s", targetChan)
				time.Sleep(2 * time.Second)
			}
			log.Println("[pck] sweep done")
		}()
	}

	logActiveMappings("port forwarding configured", rules)
	log.Println("waiting for WebRTC connection... press Ctrl+C to stop")

	if *mixkcpMode {
		p.OnICEConnected(func() {
			peerAddr := firstHostCandidate(p.RemoteCandidates())
			if peerAddr == nil {
				log.Printf("[mixkcp] no host candidate from remote, cannot send")
				return
			}
			sender, err := mixsend.NewSender(peerAddr)
			if err != nil {
				log.Printf("[mixkcp] sender: %v", err)
				return
			}
			defer sender.Close()
			log.Printf("[mixkcp] sending CONNECT to %s (rule %s, target %s:%d)",
				peerAddr, ruleID, debugRule.TargetHost, debugRule.TargetPort)

			// CONNECT payload: the PM JSON message (wire format per findings 9.8;
			// the official client's crypto layer is not reproduced — this sends the
			// correctly structured frame with the JSON body in the payload region).
			connectJSON := fmt.Sprintf(`{"seq":"6","timestamp":"%d","portMappingFrame":{"sessionId":"1","ruleId":"%s","streamId":"1","payload":"%s"}}`,
				time.Now().Unix(), ruleID, base64.StdEncoding.EncodeToString(
					[]byte(fmt.Sprintf(`{"version":1,"target_port":%d,"target_host":"%s"}`, debugRule.TargetPort, debugRule.TargetHost))))
			if err := sender.SendPMFrame(0x43, []byte(connectJSON)); err != nil {
				log.Printf("[mixkcp] send CONNECT: %v", err)
				return
			}
			log.Printf("[mixkcp] CONNECT frame sent, payload json: %s", connectJSON)

			// wait for a possible SYN_ACK (honest no-response state recorded)
			senderDeadline := time.Now().Add(10 * time.Second)
			for time.Now().Before(senderDeadline) {
				sender.SetReadDeadline(senderDeadline)
				f, err := sender.ReceivePMFrame()
				if err != nil {
					log.Printf("[mixkcp] no SYN_ACK received within deadline: %v", err)
					return
				}
				log.Printf("[mixkcp] inbound frame cmd=%#x session=%s", f.Cmd, hex.EncodeToString(f.Session))
				if f.Cmd == 0x5d {
					log.Printf("[mixkcp] SYN_ACK-like frame received: %s", hex.EncodeToString(f.Build()))
				}
			}
		})
	}

	sig.On("bmsg_push", func(ev *signaling.Event) {
		if len(ev.Args) > 0 {
			log.Printf("[signaling] bmsg_push: %s", truncate(string(ev.Args[0]), 150))
		}
	})
	sig.On("peerConnected", func(ev *signaling.Event) {
		log.Printf("[signaling] peer connected!")
	})
	sig.On("peerError", func(ev *signaling.Event) {
		log.Printf("[signaling] peer error: %s", truncate(string(ev.Args[0]), 150))
	})

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-interrupt:
		log.Println("interrupted, shutting down...")
	case <-sig.Done():
		log.Println("signaling connection closed, shutting down...")
	}
}

func doServe(client *api.Client, cfg *auth.Config, rules []tunnel.Rule, roomFile string) {
	log.Println("registering controlled device...")
	if _, err := client.InitMacDevice("UULink"); err != nil {
		log.Fatalf("register controlled device: %v", err)
	}
	if _, err := client.SetMacControllable(true); err != nil {
		log.Fatalf("enable controlled device: %v", err)
	}

	log.Println("creating room (controlled/server mode)...")
	room, err := client.CreateRoom()
	if err != nil {
		log.Fatalf("create room: %v", err)
	}
	serveRoom(client, cfg, rules, room, roomFile, nil)
}

func doGuestServe(client *api.Client, cfg *auth.Config, rules []tunnel.Rule, roomFile string) {
	log.Println("creating guest-controlled room...")
	session, err := client.CreateGuest()
	if err != nil {
		log.Fatalf("create guest: %v", err)
	}
	room, err := client.CreateGuestRoom(session)
	if err != nil {
		log.Fatalf("create guest room: %v", err)
	}
	log.Printf("guest room created: signaling=%s (%d gateways)", room.SignalingServer, len(room.SignalingList))
	serveRoom(client, cfg, rules, room, roomFile, session)
}

func serveRoom(client *api.Client, cfg *auth.Config, rules []tunnel.Rule, room *api.RoomConnectionInfo, roomFile string, guestSession *api.GuestSession) {
	log.Printf("signaling_server=%s (%d gateways)", room.SignalingServer, len(room.SignalingList))
	log.Printf("server device_id=%s", cfg.DeviceID)
	logActiveMappings("server mappings configured", rules)
	if roomFile != "" && guestSession == nil {
		if err := saveRoomFile(roomFile, room); err != nil {
			log.Fatalf("save room file: %v", err)
		}
		log.Printf("saved room connection info to %s", roomFile)
	}

	gateway := room.SignalingServer
	if gateway == "" && len(room.SignalingList) > 0 {
		gateway = room.SignalingList[0]
	}
	log.Printf("connecting to signaling gateway %s...", gateway)
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

	if guestSession != nil {
		share, err := waitForGuestConnectID(client, guestSession)
		if err != nil {
			log.Fatalf("get guest share info: %v", err)
		}
		share, err = ensureGuestShareCode(client, guestSession, share)
		if err != nil {
			log.Fatalf("prepare guest share code: %v", err)
		}
		if roomFile != "" {
			if err := saveGuestShareFile(roomFile, share); err != nil {
				log.Fatalf("save guest share file: %v", err)
			}
			log.Printf("saved guest share info to %s", roomFile)
		}
		log.Printf("guest share ready: connect_id=%s code_length=%d", share.ConnectID, len(share.ConnectCode))
	}

	sig.On("bmsg_push", func(ev *signaling.Event) {
		if len(ev.Args) > 0 {
			log.Printf("[signaling] controlled bmsg_push: %s", truncate(string(ev.Args[0]), 800))
		}
	})

	var tun *tunnel.Tunnel
	p, err := peer.NewControlled(&peer.Config{
		Signal: sig,
		OnSignalData: func(data []byte) {
			log.Printf("[pb-recv] %s", truncateStr(string(data), 200))
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
			log.Printf("report relay IP: %v", err)
		} else {
			log.Printf("reported relay IP")
		}
		if _, err := client.ReportEchoServers(room); err != nil {
			log.Printf("report relay echo servers: %v", err)
		} else {
			log.Printf("reported relay echo servers")
		}
	}

	tun = tunnel.NewTunnelWithRules(rules, &peerSender{peer: p, sig: sig})
	p.OnFileChannelOpen(func() {
		if err := tun.Start(); err != nil {
			log.Fatalf("start tunnel: %v", err)
		}
		logActiveMappings("reverse port forwarding active", rules)
	})
	defer tun.Stop()

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-interrupt:
		log.Println("interrupted, shutting down...")
	case <-sig.Done():
		log.Println("signaling connection closed, shutting down...")
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

func ensureGuestShareCode(client *api.Client, session *api.GuestSession, share *api.GuestShareInfo) (*api.GuestShareInfo, error) {
	if share.ConnectCode != "" {
		return share, nil
	}

	passCode, err := api.GenerateSharePassCode()
	if err != nil {
		return nil, err
	}
	request := &api.GuestShareUploadSignRequest{
		CanControl: true,
		ControlID:  share.ConnectID,
		Sign:       api.SharePassCodeSign(share.ConnectID, passCode),
		BackupSign: "",
	}
	if _, err := client.GuestShareUploadSign(session, request); err != nil {
		return nil, err
	}

	refreshed, err := client.GetGuestShareInfo(session)
	if err != nil {
		return nil, fmt.Errorf("refresh after upload sign: %w", err)
	}
	if refreshed.ConnectID != "" && refreshed.ConnectID != share.ConnectID {
		return nil, fmt.Errorf("connect_id changed after upload sign")
	}
	if refreshed.ConnectCode != "" {
		return refreshed, nil
	}

	refreshed.ConnectID = share.ConnectID
	refreshed.ConnectCode = passCode
	return refreshed, nil
}

type roomFileInfo struct {
	SignalingServer string   `json:"signaling_server"`
	SignalingList   []string `json:"signaling_list"`
	Token           string   `json:"token"`
}

type guestShareFileInfo struct {
	ConnectID   string `json:"connect_id"`
	ConnectCode string `json:"connect_code"`
}

func saveGuestShareFile(path string, share *api.GuestShareInfo) error {
	data, err := json.Marshal(guestShareFileInfo{
		ConnectID:   share.ConnectID,
		ConnectCode: share.ConnectCode,
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

func configuredRules(cfg *auth.Config, ruleIDFlag, localHost string, localPort int, remoteHost string, remotePort int) ([]tunnel.Rule, error) {
	var rules []tunnel.Rule
	seen := make(map[string]bool)

	appendRule := func(rule tunnel.Rule) error {
		if rule.LocalHost == "" {
			rule.LocalHost = "127.0.0.1"
		}
		if rule.TargetHost == "" {
			rule.TargetHost = "127.0.0.1"
		}
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
		if err := appendRule(tunnel.Rule{
			ID:         mapping.RuleID,
			LocalHost:  mapping.LocalHost,
			LocalPort:  mapping.LocalPort,
			TargetHost: mapping.RemoteHost,
			TargetPort: mapping.RemotePort,
		}); err != nil {
			return nil, err
		}
	}

	if localPort != 0 || remotePort != 0 {
		if localPort == 0 || remotePort == 0 {
			return nil, fmt.Errorf("both -local and -remote-port are required for a command-line mapping")
		}
		if len(cfg.Mappings) > 0 && ruleIDFlag != "" {
			return nil, fmt.Errorf("-rule-id cannot be applied globally when config mappings define their own rule_id")
		}
		if err := appendRule(tunnel.Rule{
			ID:         ruleIDFlag,
			LocalHost:  localHost,
			LocalPort:  localPort,
			TargetHost: remoteHost,
			TargetPort: remotePort,
		}); err != nil {
			return nil, err
		}
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("no mappings configured; use mappings in the config file or -local/-remote-port")
	}
	return rules, nil
}

func logActiveMappings(prefix string, rules []tunnel.Rule) {
	for _, rule := range rules {
		log.Printf("%s: %s:%d -> peer-target %s:%d (rule %s)",
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
		share, err = ensureGuestShareCode(client, session, share)
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

func truncateStr(s string, n int) string {
	return truncate(s, n)
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
