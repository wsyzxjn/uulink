package main

import (
	"fmt"
	"time"

	"github.com/wsyzxjn/uulink/pkg/api"
	"github.com/wsyzxjn/uulink/pkg/auth"
	"github.com/wsyzxjn/uulink/pkg/logging"
	"github.com/wsyzxjn/uulink/pkg/peer"
	"github.com/wsyzxjn/uulink/pkg/remoteconfig"
	"github.com/wsyzxjn/uulink/pkg/tunnel"
)

// Remote configuration mode: a distributed client fetches the share ID, code,
// and mappings from a URL (or local file) and connects as a controller without
// any local flags. A guest server can publish that document with -publish-url.

const remoteConfigFetchTimeout = 15 * time.Second

type remoteConfigOptions struct {
	url           string
	transportMode peer.TransportMode
	lanDiscovery  bool
	lanMotd       string
	ruleID        string
	mapping       string
	localHost     string
	localPort     string
	remoteHost    string
	remotePort    string
	capability    string
}

func runRemoteConfigController(client *api.Client, cfg *auth.Config, secPolicy tunnel.SecurityPolicy, options remoteConfigOptions) error {
	logging.Infof("fetching remote share configuration from %s", options.url)
	remoteCfg, err := remoteconfig.Fetch(options.url, remoteConfigFetchTimeout)
	if err != nil {
		return fmt.Errorf("fetch remote configuration: %w", err)
	}
	logging.Infof("remote configuration loaded: share_id=%s", remoteCfg.EffectiveShareID())

	// The document may require relay; a local -transport relay still wins.
	transportMode := options.transportMode
	if remoteCfg.Transport != "" {
		remoteMode, err := peer.ParseTransportMode(remoteCfg.Transport)
		if err != nil {
			return fmt.Errorf("remote configuration: %w", err)
		}
		if remoteMode == peer.TransportRelay {
			transportMode = peer.TransportRelay
		}
	}

	rules, err := remoteCfg.Rules(options.ruleID, options.mapping, options.localHost, options.localPort, options.remoteHost, options.remotePort)
	if err != nil {
		return fmt.Errorf("configure mappings from remote configuration: %w", err)
	}
	if rules == nil {
		rules = []tunnel.Rule{}
	}

	lanMotd := firstNonEmpty(options.lanMotd, remoteCfg.LANMOTD)
	return runController(client, cfg, secPolicy, controllerOptions{
		// A logged-in config joins as the user; anything else joins as a guest.
		shareJoin:     cfg.JWT != "",
		shareGuest:    cfg.JWT == "",
		shareID:       remoteCfg.EffectiveShareID(),
		shareCode:     remoteCfg.EffectiveShareCode(),
		capability:    options.capability,
		transportMode: transportMode,
		rules:         rules,
		lanDiscovery:  options.lanDiscovery || remoteCfg.LANMOTD != "",
		lanMotd:       lanMotd,
	})
}

// publishShareInfo posts the share credentials and mappings as a remote
// configuration document so clients can fetch them with -config-url.
func publishShareInfo(publishURL, secret string, share *api.GuestShareInfo, rules []tunnel.Rule) error {
	payload := &remoteconfig.RemoteShareConfig{
		ShareID:   share.ConnectID,
		ShareCode: share.ConnectCode,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	for _, rule := range rules {
		// The publishing side is the server; its listener targets are the
		// ports a client should expose locally, so the mapping is mirrored.
		payload.Mappings = append(payload.Mappings, auth.PortMapping{
			LocalHost:  rule.LocalHost,
			LocalPort:  rule.LocalPort,
			RemoteHost: rule.TargetHost,
			RemotePort: rule.TargetPort,
		})
	}
	if err := remoteconfig.Publish(publishURL, secret, payload, 10*time.Second); err != nil {
		return err
	}
	logging.Infof("published share info to %s", publishURL)
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
