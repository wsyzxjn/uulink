//go:build integration

package main

import (
	"context"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/wsyzxjn/uulink/pkg/api"
	"github.com/wsyzxjn/uulink/pkg/auth"
	"github.com/wsyzxjn/uulink/pkg/peer"
	"github.com/wsyzxjn/uulink/pkg/signaling"
	"github.com/wsyzxjn/uulink/pkg/tunnel"
)

// Opt-in only: creates a temporary accountless room and joins it with the
// configured account. Credentials and raw signaling payloads are never logged.
func TestLiveControlledSTUN(t *testing.T) {
	path := os.Getenv("UULINK_STUN_LIVE_CONFIG")
	if path == "" {
		t.Skip("set UULINK_STUN_LIVE_CONFIG to test the official gateway")
	}
	cfg, err := auth.LoadConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	client := api.NewClient(cfg)
	state, err := client.GetLoginStateContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !state.Valid {
		t.Fatal("configured login is not valid")
	}
	guestCfg := &auth.Config{}
	if err := guestCfg.Validate(); err != nil {
		t.Fatal(err)
	}
	pool := tunnel.NewAdaptiveSessionPool(1, tunnel.PolicyHealthAware, nil)
	defer pool.Close()
	tun := tunnel.NewTunnelWithRules(nil, pool)
	defer tun.Stop()
	set := newSessionSet()
	defer set.closeAll()
	code, err := api.GenerateSharePassCode()
	if err != nil {
		t.Fatal(err)
	}
	rt, share, err := startPooledGuestServer(ctx, api.NewClient(guestCfg), guestCfg, tun, pool, set, "stun-probe", "uulink-stun-probe", guestShareOptions{AuthMode: api.ShareAuthCustom, CustomCode: code}, nil, tunnel.SecurityPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.close()
	events := make(chan []json.RawMessage, 1)
	rt.sig.On("be-controlled", func(ev *signaling.Event) {
		select {
		case events <- ev.Args:
		default:
		}
	})
	room, err := client.JoinRoomByShareCodeContext(ctx, share.ConnectID, share.ConnectCode)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := connectSignaling(room, true, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer sig.Close()
	controller, err := peer.NewController(&peer.Config{Signal: sig, DeviceID: cfg.DeviceID, VersionName: cfg.Identity().VersionName, Platform: cfg.Identity().Platform, Network: cfg.Network})
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	select {
	case args := <-events:
		for _, arg := range args {
			var object any
			if err := json.Unmarshal(arg, &object); err != nil {
				t.Fatal("invalid control event JSON")
			}
			logSTUNShape(t, object, "event")
		}
	case <-ctx.Done():
		t.Fatal("no be-controlled event received")
	}
}

func logSTUNShape(t *testing.T, value any, path string) {
	t.Helper()
	switch value := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		t.Logf("%s keys=%v", path, keys)
		for _, key := range keys {
			logSTUNShape(t, value[key], path+"."+key)
		}
	case []any:
		for _, item := range value {
			logSTUNShape(t, item, path+"[]")
		}
	case string:
		if strings.HasPrefix(value, "stun:") || strings.HasPrefix(value, "stuns:") {
			t.Logf("%s=%s", path, value)
		}
	}
}
