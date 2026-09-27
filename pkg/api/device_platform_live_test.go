package api

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/wsyzxjn/uulink/pkg/auth"
)

// Opt-in only. Probe registration and guest-room availability using temporary
// unbound identities; it never binds devices to a user's logged-in account.
func TestLivePlatformRegistration(t *testing.T) {
	if os.Getenv("UULINK_PLATFORM_LIVE") != "1" {
		t.Skip("set UULINK_PLATFORM_LIVE=1 to verify registration against UU")
	}
	for _, platform := range []int{auth.WindowsPlatform, auth.MacPlatform} {
		t.Run(strconv.Itoa(platform), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cfg := &auth.Config{Platform: platform}
			client := NewClient(cfg)
			session, identity, err := client.CreateUnboundGuestContext(ctx, "uulink-platform-probe")
			if err != nil {
				t.Fatal(err)
			}
			if session.Platform != platform || identity.Platform != platform || cfg.UnboundPlatform != platform {
				t.Fatal("registered platform changed unexpectedly")
			}
			if _, err := client.GuestSetDeviceControllableContext(ctx, session, true); err != nil {
				t.Fatal(err)
			}
			room, err := client.CreateGuestRoomContext(ctx, session)
			if err != nil {
				t.Fatal(err)
			}
			if room.Token == "" || room.SignalingServer == "" {
				t.Fatal("room credentials missing")
			}
			t.Logf("platform=%d registration, guest session, controllability and room creation succeeded", platform)
		})
	}
}
