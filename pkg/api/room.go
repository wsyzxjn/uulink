package api

import (
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
	Raw             map[string]any
}

// CreateRoom calls POST /api/v1/room/create (server/controlled side).
func (c *Client) CreateRoom() (*RoomConnectionInfo, error) {
	resp, err := c.Do("POST", "/api/v1/room/create", map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("room create: %w", err)
	}

	if code, ok := resp["code"].(float64); ok && code != 0 {
		return nil, fmt.Errorf("room create failed, code %v: %v", code, resp["msg"])
	}

	data, ok := resp["data"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("no data in room create response: %v", resp)
	}

	return parseRoomConnectionInfo(data), nil
}

// JoinRoomByDevice calls POST /api/v1/room/join/by_device/<id> (controller side).
// Returns the room connection info if successful.
func (c *Client) JoinRoomByDevice(deviceID string, forceJoin bool) (*RoomConnectionInfo, error) {
	resp, err := c.Do("POST", "/api/v1/room/join/by_device/"+deviceID, map[string]bool{"force_join": forceJoin})
	if err != nil {
		return nil, fmt.Errorf("room join: %w", err)
	}

	if code, ok := resp["code"].(float64); ok && code != 0 {
		return nil, fmt.Errorf("room join failed, code %v: %v", code, resp["msg"])
	}

	data, ok := resp["data"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("no data in room join response: %v", resp)
	}

	return parseRoomConnectionInfo(data), nil
}

// RefetchRoomJoin refreshes room join credentials using a signaling reconnect key.
func (c *Client) RefetchRoomJoin(token string) (*RoomConnectionInfo, error) {
	resp, err := c.Do("POST", "/api/v1/room/join/refetch", map[string]string{"token": token})
	if err != nil {
		return nil, fmt.Errorf("room join refetch: %w", err)
	}

	if code, ok := resp["code"].(float64); ok && code != 0 {
		return nil, fmt.Errorf("room join refetch failed, code %v: %v", code, resp["msg"])
	}

	data, ok := resp["data"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("no data in room join refetch response")
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
