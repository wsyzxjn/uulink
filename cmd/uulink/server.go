package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/wsyzxjn/uulink/pkg/api"
	"github.com/wsyzxjn/uulink/pkg/auth"
	"github.com/wsyzxjn/uulink/pkg/logging"
	"github.com/wsyzxjn/uulink/pkg/peer"
	"github.com/wsyzxjn/uulink/pkg/proto/gvpb"
	"github.com/wsyzxjn/uulink/pkg/signaling"
	"github.com/wsyzxjn/uulink/pkg/tunnel"
)

func doServe(ctx context.Context, client *api.Client, cfg *auth.Config, rules []tunnel.Rule, roomFile string, policy tunnel.SecurityPolicy, targetSessions int) error {
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
	return serveRoom(ctx, client, cfg, rules, room, roomFile, nil, guestShareOptions{}, policy, targetSessions)
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

func doGuestServe(ctx context.Context, client *api.Client, cfg *auth.Config, rules []tunnel.Rule, roomFile string, shareOptions guestShareOptions, policy tunnel.SecurityPolicy, targetSessions int) error {
	session, err := client.CreateGuest()
	if err != nil {
		return fmt.Errorf("create guest: %w", err)
	}
	room, err := client.CreateGuestRoom(session)
	if err != nil {
		return fmt.Errorf("create guest room: %w", err)
	}
	return serveRoom(ctx, client, cfg, rules, room, roomFile, session, shareOptions, policy, targetSessions)
}

func doUnboundGuestServe(ctx context.Context, client *api.Client, cfg *auth.Config, rules []tunnel.Rule, roomFile string, shareOptions guestShareOptions, policy tunnel.SecurityPolicy, targetSessions int) error {
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
	return serveRoom(ctx, client, cfg, rules, room, roomFile, session, shareOptions, policy, targetSessions)
}

func serveRoom(ctx context.Context, client *api.Client, cfg *auth.Config, rules []tunnel.Rule, room *api.RoomConnectionInfo, roomFile string, guestSession *api.GuestSession, shareOptions guestShareOptions, policy tunnel.SecurityPolicy, targetSessions int) error {
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

	sig, err := connectSignaling(room, false)
	if err != nil {
		return fmt.Errorf("signaling connect: %w", err)
	}
	defer sig.Close()
	if err := ctx.Err(); err != nil {
		return nil
	}

	// share is updated by the push worker and read once below, so every
	// access after the handler is installed goes through shareMu.
	var shareMu sync.Mutex
	var share *api.GuestShareInfo
	pushes := newPushQueue(sig.Done())
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
		if guestSession == nil || push.Data.ControlID == "" {
			if push.Type == "remote_control" {
				logging.Warnf("remote control push has no control_id")
			} else {
				logging.Debugf("[signaling] controlled bmsg_push type=%q", push.Type)
			}
			return
		}

		// The push is answered with several API round trips; the queue keeps
		// them off the signaling read loop and in arrival order.
		pushes.submit(func() {
			shareMu.Lock()
			defer shareMu.Unlock()
			switch push.Type {
			case "remote_control":
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

			case "get_control_mode":
				logging.Debugf("get_control_mode received")
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

			default:
				logging.Debugf("[signaling] controlled bmsg_push type=%q", push.Type)
			}
		})
	})

	if guestSession != nil {
		shareMu.Lock()
		current := *share
		shareMu.Unlock()
		if roomFile != "" {
			if err := saveGuestShareFile(roomFile, &current); err != nil {
				return fmt.Errorf("save guest share file: %w", err)
			}
			logging.Debugf("saved guest share info to %s", roomFile)
		}
		if shareOptions.AuthMode == api.ShareAuthCustom {
			logging.Infof("custom assistance ready: connect_id=%s custom_code=%s", current.ConnectID, current.ConnectCode)
			logging.Infof("client command: uulink share join -id %s -code %s", current.ConnectID, current.ConnectCode)
		} else {
			logging.Infof("guest share ready: connect_id=%s connect_code=%s", current.ConnectID, current.ConnectCode)
		}
		if shareOptions.ConfigPath != "" && (cfg.ShareID != current.ConnectID || cfg.CustomCode != shareOptions.CustomCode) {
			// Remember the share so the same ID and custom code are reused
			// next time this server starts.
			cfg.ShareID = current.ConnectID
			cfg.CustomCode = shareOptions.CustomCode
			if err := auth.SaveConfigFile(shareOptions.ConfigPath, cfg); err != nil {
				return fmt.Errorf("save share identity: %w", err)
			}
		}
		if shareOptions.PublishURL != "" {
			if err := publishShareInfo(shareOptions.PublishURL, shareOptions.PublishSecret, &current, rules); err != nil {
				return fmt.Errorf("publish share info: %w", err)
			}
		}
	}

	var tun *tunnel.Tunnel
	wired := make(chan struct{})
	var primarySession tunnel.Session
	var adaptivePool *tunnel.AdaptiveSessionPool
	p, err := peer.NewControlled(&peer.Config{
		Signal: sig,
		OnSignalData: func(data []byte) {
			<-wired
			frame := tunnel.DecodeFrameForTunnel(data)
			if frame == nil {
				return
			}
			adaptivePool.Pool().ObserveReceived("primary", len(data))
			if frame.Type == gvpb.TypeConnect {
				adaptivePool.Pool().BindStream(frame.RuleID, frame.StreamID, primarySession)
			}
			tun.HandleFrame(frame)
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
	adaptivePool = tunnel.NewAdaptiveSessionPool(targetSessions, tunnel.PolicyHealthAware, nil)
	primarySession = tunnel.NewSimpleSession("primary", &peerSender{peer: p}, nil)
	adaptivePool.Pool().AddSession(primarySession)
	p.OnModeChange(adaptivePool.OnModeDetected)

	tun = tunnel.NewTunnelWithRules(rules, adaptivePool)
	tun.SetSecurityPolicy(policy)
	close(wired)

	expandSet := newSessionSet()
	defer expandSet.closeAll()
	p.OnTextMessage(serveExpandRequests(p, targetSessions-1, newExpansionMinter(cfg, tun, adaptivePool, expandSet, shareOptions, policy)))
	runErr := make(chan error, 1)
	monitorPrimary(expandSet.ctx, p, runErr)
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
