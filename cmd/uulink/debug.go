package main

import (
	"fmt"
	"time"

	"github.com/wsyzxjn/uulink/pkg/api"
	"github.com/wsyzxjn/uulink/pkg/logging"
	"github.com/wsyzxjn/uulink/pkg/signaling"
)

func doGuestTest(client *api.Client) error {
	session, err := client.CreateGuest()
	if err != nil {
		return fmt.Errorf("create guest: %w", err)
	}
	logging.Infof("guest session created: guest_id_len=%d token_len=%d user_id_len=%d device_id_len=%d",
		len(session.GuestID), len(session.Token), len(session.UserID), len(session.DeviceID))

	room, err := client.CreateGuestRoom(session)
	if err != nil {
		return fmt.Errorf("create guest room: %w", err)
	}
	logging.Infof("guest room created: signaling=%s gateways=%d token_len=%d",
		room.SignalingServer, len(room.SignalingList), len(room.Token))
	logging.Infof("guest room raw keys: %v", mapKeys(room.Raw))

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
		logging.Infof("guest signaling namespace connected")
	case <-time.After(5 * time.Second):
		logging.Infof("guest signaling namespace connect timeout")
	case <-sig.Done():
		return fmt.Errorf("guest signaling closed before namespace connection")
	}

	time.Sleep(2 * time.Second)

	share, err := client.GetGuestShareInfo(session)
	if err != nil {
		return fmt.Errorf("get guest share info: %w", err)
	}
	logging.Infof("guest share info: alias=%q connect_id=%q connect_code_len=%d",
		share.Alias, share.ConnectID, len(share.ConnectCode))
	logging.Infof("guest share info raw keys: %v", mapKeys(share.Raw))

	if share.ConnectCode == "" {
		logging.Infof("connect_code is empty; uploading generated share pass code")
		share, err = ensureGuestShareCode(client, session, share, guestShareOptions{AuthMode: api.ShareAuthTemporary})
		if err != nil {
			return fmt.Errorf("upload guest share sign: %w", err)
		}
		logging.Infof("guest share info refreshed: alias=%q connect_id=%q connect_code_len=%d",
			share.Alias, share.ConnectID, len(share.ConnectCode))

	}

	if share.ConnectCode == "" {
		return fmt.Errorf("guest share code was not generated")
	}

	logging.Infof("attempting join by share code as logged-in controller")
	joined, err := client.JoinRoomByShareCode(share.ConnectID, share.ConnectCode)
	if err != nil {
		logging.Infof("join by share code as logged-in controller failed: %v", err)
	} else {
		logging.Infof("joined guest share room as logged-in controller: signaling=%s gateways=%d token_len=%d",
			joined.SignalingServer, len(joined.SignalingList), len(joined.Token))
	}

	logging.Infof("attempting join by share code as guest controller")
	guestJoined, err := client.JoinRoomByShareCodeWithGuest(session, share.ConnectID, share.ConnectCode)
	if err != nil {
		return fmt.Errorf("join by share code as guest controller: %w", err)
	}
	logging.Infof("joined guest share room as guest controller: signaling=%s gateways=%d token_len=%d",
		guestJoined.SignalingServer, len(guestJoined.SignalingList), len(guestJoined.Token))
	return nil
}
