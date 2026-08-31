// Package api implements the UU Remote REST API client.
package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/user/uulink/pkg/auth"
)

const baseURL = "https://api.nrd.nie.163.com"

// Client wraps HTTP calls to the UU Remote REST API.
type Client struct {
	cfg  *auth.Config
	http *http.Client
}

// ResponseError represents a non-zero business response code from the UU Remote API.
type ResponseError struct {
	Code     int
	Message  string
	Response map[string]any
}

func (e *ResponseError) Error() string {
	return fmt.Sprintf("code %d: %s", e.Code, e.Message)
}

// NewClient creates an API client with the given auth config.
func NewClient(cfg *auth.Config) *Client {
	return &Client{
		cfg: cfg,
		// The official QR-code login status request is a 60 second long poll.
		http: &http.Client{Timeout: 60 * time.Second},
	}
}

// Do sends an authenticated request and returns the parsed JSON response.
func (c *Client) Do(method, path string, body any) (map[string]any, error) {
	var bodyBytes []byte
	var bodyStr string
	if body != nil {
		var err error
		bodyBytes, err = json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal body: %w", err)
		}
		bodyStr = string(bodyBytes)
	}

	fullURL := baseURL + path
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	headers := auth.BuildHeaders(c.cfg, ts)
	sign := auth.Sign(method, fullURL, headers, bodyStr)
	headers["X-Param-SIGN"] = sign

	var bodyReader io.Reader
	if bodyBytes != nil {
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequest(method, fullURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http do: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	var result map[string]any
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("status %d, unmarshal: %w (body: %s)", resp.StatusCode, err, string(respBody[:min(len(respBody), 200)]))
	}

	return result, nil
}

// GetUserInfo fetches current user info.
func (c *Client) GetUserInfo() (map[string]any, error) {
	return c.Do("GET", "/api/v1/user/info", nil)
}

// GetDeviceList fetches the device list.
func (c *Client) GetDeviceList() (map[string]any, error) {
	return c.Do("GET", "/api/v1/device/list", nil)
}

// JoinRoom joins a room by device ID.
func (c *Client) JoinRoom(deviceID string, forceJoin bool) (map[string]any, error) {
	return c.Do("POST", "/api/v1/room/join/by_device/"+deviceID, map[string]bool{"force_join": forceJoin})
}

// RoomJoinResponse holds parsed room join data.
type RoomJoinResponse struct {
	RoomID    string         `json:"room_id"`
	NRDAuth   string         `json:"nrd_auth"`   // X-NRD-AUTH token for signaling
	ReconnKey string         `json:"reconn_key"` // X-NRD-RECONN-KEY for reconnection
	Gateways  []string       `json:"gateways"`   // signaling gateway URLs
	RawData   map[string]any `json:"-"`          // full response data for debugging
}

// ParseRoomJoin extracts room connection info from a join response.
// The response format is explored at runtime; this tries multiple field name variants.
func ParseRoomJoin(resp map[string]any) (*RoomJoinResponse, error) {
	data, ok := resp["data"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("no data field in response: %v", resp)
	}

	rj := &RoomJoinResponse{RawData: data}

	// Try common field names for room ID
	for _, key := range []string{"room_id", "roomId", "id"} {
		if v, ok := data[key].(string); ok && v != "" {
			rj.RoomID = v
			break
		}
	}

	// NRD auth token — may be nested
	for _, key := range []string{"nrd_auth", "auth", "token", "nrd_token", "auth_token"} {
		if v, ok := data[key].(string); ok && v != "" {
			rj.NRDAuth = v
			break
		}
	}

	// Reconnection key
	for _, key := range []string{"reconn_key", "reconnKey", "reconnect_key"} {
		if v, ok := data[key].(string); ok && v != "" {
			rj.ReconnKey = v
			break
		}
	}

	// Gateways list
	for _, key := range []string{"gateways", "gateway_list", "sig_urls", "signaling_urls"} {
		if gws, ok := data[key].([]any); ok {
			for _, g := range gws {
				if s, ok := g.(string); ok {
					rj.Gateways = append(rj.Gateways, s)
				}
				if m, ok := g.(map[string]any); ok {
					if s, ok := m["url"].(string); ok {
						rj.Gateways = append(rj.Gateways, s)
					}
				}
			}
			if len(rj.Gateways) > 0 {
				break
			}
		}
	}

	return rj, nil
}
