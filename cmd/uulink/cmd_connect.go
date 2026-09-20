package main

import (
	"context"
	"flag"

	"github.com/wsyzxjn/uulink/pkg/api"
	"github.com/wsyzxjn/uulink/pkg/peer"
)

// connect is the controlling side for same-account devices and for remote
// share configurations (the tslink-style zero-config distribution mode).

type connectOptions struct {
	deviceID  string
	configURL string
	mapping   mappingFlags
	policy    policyFlags
	sessions  sessionFlags
	ctrl      controllerFlags
	// Debugging aids.
	roomFile  string
	allowSelf bool
}

func connectCommand() *command {
	opts := &connectOptions{}
	return &command{
		name:    "connect",
		summary: "Connect to a device of the same account, or through a remote share configuration",
		long: `With -device the target must be a device of this account that runs
'uulink serve'. With -config-url the share ID, code, and mappings are fetched
from an HTTP(S) URL or a local file; the controlling side still has to be logged
in (see 'uulink login'). Mapping flags add local listeners that reach services
on the target.`,
		bind: func(fs *flag.FlagSet) {
			fs.StringVar(&opts.deviceID, "device", "", "device ID to connect to (see 'uulink list')")
			fs.StringVar(&opts.configURL, "config-url", DefaultConfigURL, "URL or file path of a remote share configuration")
			opts.mapping.bind(fs)
			opts.policy.bind(fs)
			opts.sessions.bind(fs)
			opts.ctrl.bind(fs)
			fs.StringVar(&opts.roomFile, "room-file", "", debugUsagePrefix+"join the room described by this file instead of an API join (same-host E2E)")
			fs.BoolVar(&opts.allowSelf, "allow-self", false, debugUsagePrefix+"allow the target to be this config's own device (same-host E2E)")
		},
		run: func(g *globalOptions) error { return runConnect(g, opts) },
	}
}

func runConnect(g *globalOptions, opts *connectOptions) error {
	transportMode, err := opts.ctrl.transportMode()
	if err != nil {
		return err
	}
	// An explicit -device wins over a baked-in default URL; two explicit
	// targets are a mistake.
	useRemoteConfig := opts.configURL != "" && (opts.deviceID == "" || opts.configURL != DefaultConfigURL)
	if useRemoteConfig && opts.deviceID != "" {
		return usageErrorf("-device and -config-url select different targets; pass only one")
	}

	// Remote-config clients create their identity on first start; a
	// same-account join needs the saved login.
	cfg, err := loadConfig(g, useRemoteConfig)
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

	if useRemoteConfig {
		remoteOptions := remoteConfigOptions{
			url:            opts.configURL,
			lanDiscovery:   opts.ctrl.lanDiscovery,
			lanMotd:        opts.ctrl.lanMotd,
			ruleID:         opts.mapping.ruleID,
			mapping:        opts.mapping.mapping,
			localHost:      opts.mapping.localHost,
			localPort:      opts.mapping.localPort,
			remoteHost:     opts.mapping.remoteHost,
			remotePort:     opts.mapping.remotePort,
			capability:     opts.ctrl.capability,
			p2pTimeout:     opts.ctrl.p2pTimeout,
			targetSessions: sessions.target,
			autoSessions:   sessions.auto,
		}
		return runWithRelayFallback(transportMode, opts.ctrl.p2pTimeout, func(ctx context.Context, mode peer.TransportMode) error {
			remoteOptions.transportMode = mode
			return runRemoteConfigController(ctx, client, cfg, policy, remoteOptions)
		})
	}

	rules, err := opts.mapping.rules(cfg)
	if err != nil {
		return err
	}
	targetDevID := firstNonEmpty(opts.deviceID, cfg.DeviceID)
	if opts.roomFile == "" && (targetDevID == "" || (targetDevID == cfg.DeviceID && !opts.allowSelf)) {
		return usageErrorf("-device is required and must name another device of this account (see 'uulink list')")
	}
	controller := controllerOptions{
		deviceID:        targetDevID,
		controlDeviceID: opts.ctrl.controlDeviceID,
		roomFile:        opts.roomFile,
		capability:      opts.ctrl.capability,
		pckSweep:        *experimentPCKSweep,
		mixKCP:          *experimentMixKCP,
		targetSessions:  sessions.target,
		autoSessions:    sessions.auto,
		rules:           rules,
		lanDiscovery:    opts.ctrl.lanDiscovery,
		lanMotd:         opts.ctrl.lanMotd,
		configPath:      g.configPath,
		p2pTimeout:      opts.ctrl.p2pTimeout,
	}
	return runWithRelayFallback(transportMode, opts.ctrl.p2pTimeout, func(ctx context.Context, mode peer.TransportMode) error {
		controller.transportMode = mode
		return runController(ctx, client, cfg, policy, controller)
	})
}
