package api

import (
	"context"
	"fmt"
)

// RoomConnectionInfo holds everything needed to connect to the signaling gateway.
type RoomConnectionInfo struct {
	RoomID          string   // may be empty (token identifies the room)
	Token           string   // X-NRD-AUTH token
	SignalingServer string   // primary gateway URL
	SignalingList   []string // all gateway URLs
	ReportURL       string   // relay report URL
	ReportToken     string   // relay report token
	// IsRoomFileController marks a controller that loaded the room from a
	// file written by the guest. Its signaling token was issued for the
	// controlled role, so the controller must connect with Controlling=false.
	IsRoomFileController bool
	Raw                  map[string]any
}

// CreateRoom calls POST /api/v1/room/create (server/controlled side).
func (c *Client) CreateRoom() (*RoomConnectionInfo, error) {
	return c.CreateRoomContext(context.Background())
}

// CreateRoomContext creates a room using ctx.
func (c *Client) CreateRoomContext(ctx context.Context) (*RoomConnectionInfo, error) {
	resp, err := c.DoContext(ctx, "POST", "/api/v1/room/create", map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("room create: %w", err)
	}

	data, err := responseData(resp, "room create")
	if err != nil {
		return nil, err
	}

	return parseRoomConnectionInfo(data), nil
}

// JoinRoomByDevice calls POST /api/v1/room/join/by_device/<id> (controller side).
// Returns the room connection info if successful.
func (c *Client) JoinRoomByDevice(deviceID string, forceJoin bool) (*RoomConnectionInfo, error) {
	return c.JoinRoomByDeviceContext(context.Background(), deviceID, forceJoin)
}

// JoinRoomByDeviceContext joins a room by device ID using ctx.
func (c *Client) JoinRoomByDeviceContext(ctx context.Context, deviceID string, forceJoin bool) (*RoomConnectionInfo, error) {
	resp, err := c.DoContext(ctx, "POST", "/api/v1/room/join/by_device/"+deviceID, map[string]bool{"force_join": forceJoin})
	if err != nil {
		return nil, fmt.Errorf("room join: %w", err)
	}

	data, err := responseData(resp, "room join")
	if err != nil {
		return nil, err
	}

	return parseRoomConnectionInfo(data), nil
}

// RefetchRoomJoin refreshes room join credentials using a signaling reconnect key.
func (c *Client) RefetchRoomJoin(token string) (*RoomConnectionInfo, error) {
	return c.RefetchRoomJoinContext(context.Background(), token)
}

// RefetchRoomJoinContext refreshes room join credentials using ctx.
func (c *Client) RefetchRoomJoinContext(ctx context.Context, token string) (*RoomConnectionInfo, error) {
	resp, err := c.DoContext(ctx, "POST", "/api/v1/room/join/refetch", map[string]string{"token": token})
	if err != nil {
		return nil, fmt.Errorf("room join refetch: %w", err)
	}

	data, err := responseData(resp, "room join refetch")
	if err != nil {
		return nil, err
	}

	return parseRoomConnectionInfo(data), nil
}

func parseRoomConnectionInfo(data map[string]any) *RoomConnectionInfo {
	info := &RoomConnectionInfo{Raw: data}
	info.Token, _ = data["token"].(string)
	info.SignalingServer, _ = data["signaling_server"].(string)
	info.ReportURL, _ = data["report_url"].(string)
	info.ReportToken, _ = data["report_token"].(string)
	if list, ok := data["signaling_list"].([]any); ok {
		for _, g := range list {
			if s, ok := g.(string); ok {
				info.SignalingList = append(info.SignalingList, s)
			}
		}
	}
	return info
}
