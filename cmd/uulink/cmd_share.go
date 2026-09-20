package main

import (
	"context"
	"flag"
	"fmt"

	"github.com/wsyzxjn/uulink/pkg/api"
	"github.com/wsyzxjn/uulink/pkg/logging"
	"github.com/wsyzxjn/uulink/pkg/peer"
)

// share groups the remote-assistance modes: the served side stays accountless
// and publishes a connect ID plus a code; the controlling side joins with them.

func shareCommand() *command {
	return &command{
		name:    "share",
		summary: "Accountless sharing by connect ID and verification code",
		sub: []*command{
			shareServeCommand(),
			shareJoinCommand(),
			shareInfoCommand(),
		},
	}
}

type shareServeOptions struct {
	account       bool
	custom        bool
	customCode    string
	authMode      string
	publishURL    string
	publishSecret string
	mapping       mappingFlags
	policy        policyFlags
	sessions      sessionFlags
	// Debugging aids.
	roomFile  string
	controlID string
}

func shareServeCommand() *command {
	opts := &shareServeOptions{}
	return &command{
		name:    "serve",
		summary: "Serve this machine through a share code (no account needed)",
		long: `Registers an accountless device, creates a room, and prints the connect ID
and code a controller passes to 'uulink share join'. With -custom (or a
-custom-code) the code is fixed and, together with the connect ID, saved to the
config file so restarts keep the same entry point. -account reuses the device
identity already stored in the config instead of registering a new one.`,
		bind: func(fs *flag.FlagSet) {
			fs.BoolVar(&opts.account, "account", false, "serve the device identity already in the config (from 'uulink login' or an earlier 'share serve') instead of registering a new accountless device")
			fs.BoolVar(&opts.custom, "custom", false, "use a fixed custom verification code; one is generated when -custom-code is empty")
			fs.StringVar(&opts.customCode, "custom-code", "", "custom verification code (8-16 letters and digits); implies -custom")
			fs.StringVar(&opts.authMode, "auth-mode", "temporary", "share authorization mode: temporary, custom, or both")
			fs.StringVar(&opts.publishURL, "publish-url", "", "webhook URL that receives the share configuration once the room is ready")
			fs.StringVar(&opts.publishSecret, "publish-secret", "", "bearer token sent with -publish-url requests")
			opts.mapping.bind(fs)
			opts.policy.bind(fs)
			opts.sessions.bind(fs)
			fs.StringVar(&opts.roomFile, "room-file", "", debugUsagePrefix+"write the share info (and room info) to this file for a same-host controller")
			fs.StringVar(&opts.controlID, "control-id", "", debugUsagePrefix+"controller control ID used for the share verification sign (defaults to the connect ID)")
		},
		run: func(g *globalOptions) error { return runShareServe(g, opts) },
	}
}

func runShareServe(g *globalOptions, opts *shareServeOptions) error {
	authMode, err := api.ParseShareAuthMode(opts.authMode)
	if err != nil {
		return usageErrorf("parse share auth mode: %w", err)
	}
	// -account reuses the identity saved in the config, so the file has to
	// exist; an accountless server creates its identity on first start.
	cfg, err := loadConfig(g, !opts.account)
	if err != nil {
		return err
	}

	// A custom code comes from the flag or the config file. Any custom code
	// switches the authorization to custom mode unless "both" was requested.
	customCode := firstNonEmpty(opts.customCode, cfg.CustomCode)
	useCustom := opts.custom || customCode != ""
	if useCustom && authMode == api.ShareAuthTemporary {
		authMode = api.ShareAuthCustom
	}
	if customCode != "" {
		if err := api.ValidateCustomShareCode(customCode); err != nil {
			return usageErrorf("validate custom code: %w", err)
		}
	}
	if useCustom && customCode == "" {
		customCode, err = api.GenerateCustomShareCode()
		if err != nil {
			return fmt.Errorf("generate custom code: %w", err)
		}
		logging.Infof("generated custom verification code: %s", customCode)
	}
	shareOptions := guestShareOptions{
		ControlID:     opts.controlID,
		AuthMode:      authMode,
		CustomCode:    customCode,
		ConfigPath:    g.configPath,
		PublishURL:    opts.publishURL,
		PublishSecret: opts.publishSecret,
	}

	rules, err := opts.mapping.rules(cfg)
	if err != nil {
		return err
	}
	policy, err := opts.policy.policy(cfg)
	if err != nil {
		return err
	}
	sessions, err := opts.sessions.resolve(cfg)
	if err != nil {
		return err
	}
	client := api.NewClient(cfg)

	if opts.account {
		return recoverTunnel(func(ctx context.Context) error {
			return doGuestServe(ctx, client, cfg, rules, opts.roomFile, shareOptions, policy, sessions.target)
		})
	}
	// A fixed custom code has to keep its published identity, so that mode
	// starts as a single session and grows in band once a controller reports
	// a relay. A fixed manual pool still mints every room up front, which
	// keeps -room-file usable for controllers that join by hand.
	if sessions.target > 1 && !useCustom && !sessions.auto {
		return recoverTunnel(func(ctx context.Context) error {
			return doMultiSessionUnboundGuestServe(ctx, cfg, rules, opts.roomFile, shareOptions, policy, sessions.target)
		})
	}
	return recoverTunnel(func(ctx context.Context) error {
		return doUnboundGuestServe(ctx, client, cfg, rules, opts.roomFile, shareOptions, policy, sessions.target)
	})
}

type shareJoinOptions struct {
	id         string
	code       string
	customCode string
	guest      bool
	confirm    bool
	controlID  string
	mapping    mappingFlags
	policy     policyFlags
	sessions   sessionFlags
	ctrl       controllerFlags
	// Debugging aids.
	roomFile string
}

func shareJoinCommand() *command {
	opts := &shareJoinOptions{}
	return &command{
		name:    "join",
		summary: "Connect to a served share by connect ID and code",
		long: `The connect ID and code default to share_id and share_code / custom_code in
the config file, so a distributed client can start without flags. Several
comma-separated IDs and codes join one pooled relay session per share. The
controlling side has to be logged in: the API rejects guest identities on share
joins.`,
		bind: func(fs *flag.FlagSet) {
			fs.StringVar(&opts.id, "id", "", "connect ID of the share (or comma-separated IDs for a pooled join)")
			fs.StringVar(&opts.code, "code", "", "verification code of the share (temporary or custom; comma-separated for a pooled join)")
			fs.StringVar(&opts.customCode, "custom-code", "", "custom verification code; same as -code, kept for symmetry with 'share serve'")
			fs.BoolVar(&opts.guest, "guest", false, "join with an ephemeral guest identity instead of the saved login (currently rejected by the API)")
			fs.BoolVar(&opts.confirm, "confirm", false, "join by server-side confirmation instead of a code")
			fs.StringVar(&opts.controlID, "control-id", "", "controller control ID for -confirm (generated when omitted)")
			opts.mapping.bind(fs)
			opts.policy.bind(fs)
			opts.sessions.bind(fs)
			opts.ctrl.bind(fs)
			fs.StringVar(&opts.roomFile, "room-file", "", debugUsagePrefix+"read the share info from this file written by 'share serve -room-file'")
		},
		run: func(g *globalOptions) error { return runShareJoin(g, opts) },
	}
}

func runShareJoin(g *globalOptions, opts *shareJoinOptions) error {
	transportMode, err := opts.ctrl.transportMode()
	if err != nil {
		return err
	}
	if opts.customCode != "" {
		if err := api.ValidateCustomShareCode(opts.customCode); err != nil {
			return usageErrorf("validate custom code: %w", err)
		}
	}
	cfg, err := loadConfig(g, true)
	if err != nil {
		return err
	}
	rules, err := opts.mapping.rules(cfg)
	if err != nil {
		return err
	}
	policy, err := opts.policy.policy(cfg)
	if err != nil {
		return err
	}
	sessions, err := opts.sessions.resolve(cfg)
	if err != nil {
		return err
	}

	id := firstNonEmpty(opts.id, cfg.ShareID)
	code := firstNonEmpty(opts.code, opts.customCode, cfg.CustomCode, cfg.ShareCode)
	guest := opts.guest || cfg.JWT == ""

	// A controller can drive several pooled sessions at once when given one
	// share per session (comma-separated flags or a multi-share room file).
	shares, err := multiSessionShares(opts.roomFile, !guest && !opts.confirm, guest && !opts.confirm, id, code)
	if err != nil {
		return usageErrorf("%w", err)
	}
	if len(shares) == 1 && opts.roomFile != "" {
		id, code = shares[0].ID, shares[0].Code
	}
	if id == "" {
		return usageErrorf("-id is required (or share_id in the config file)")
	}
	if !opts.confirm && code == "" {
		return usageErrorf("-code is required (or share_code / custom_code in the config file)")
	}
	if guest && !opts.guest {
		logging.Warnf("no login saved in %s; joining with a guest identity, which the API currently rejects (run 'uulink login')", g.configPath)
	}
	client := api.NewClient(cfg)

	if len(shares) > 1 {
		return runWithRelayFallback(transportMode, opts.ctrl.p2pTimeout, func(ctx context.Context, mode peer.TransportMode) error {
			return doMultiSessionController(ctx, client, cfg, rules, shares, multiSessionControllerOptions{
				transportMode: mode,
				useGuest:      guest,
				shareIDs:      id,
				shareCodes:    code,
				p2pTimeout:    opts.ctrl.p2pTimeout,
			}, policy)
		})
	}

	controller := controllerOptions{
		controlDeviceID:   opts.ctrl.controlDeviceID,
		shareJoin:         !guest && !opts.confirm,
		shareGuest:        guest && !opts.confirm,
		shareConfirmation: opts.confirm,
		shareControlID:    opts.controlID,
		shareID:           id,
		shareCode:         code,
		capability:        opts.ctrl.capability,
		pckSweep:          *experimentPCKSweep,
		mixKCP:            *experimentMixKCP,
		targetSessions:    sessions.target,
		autoSessions:      sessions.auto,
		rules:             rules,
		lanDiscovery:      opts.ctrl.lanDiscovery,
		lanMotd:           opts.ctrl.lanMotd,
		configPath:        g.configPath,
		p2pTimeout:        opts.ctrl.p2pTimeout,
	}
	return runWithRelayFallback(transportMode, opts.ctrl.p2pTimeout, func(ctx context.Context, mode peer.TransportMode) error {
		controller.transportMode = mode
		return runController(ctx, client, cfg, policy, controller)
	})
}

func shareInfoCommand() *command {
	var id string
	return &command{
		name:    "info",
		summary: "Query the control mode of a share and exit",
		bind: func(fs *flag.FlagSet) {
			fs.StringVar(&id, "id", "", "connect ID of the share")
		},
		run: func(g *globalOptions) error {
			if id == "" {
				return usageErrorf("-id is required")
			}
			cfg, err := loadConfig(g, false)
			if err != nil {
				return err
			}
			response, err := api.NewClient(cfg).GetShareControlMode(id)
			if err != nil {
				return fmt.Errorf("query share control mode: %w", err)
			}
			logging.Infof("share control mode query complete: code=%v", response["code"])
			return nil
		},
	}
}
