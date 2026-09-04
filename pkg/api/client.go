// Package api implements the UU Remote REST API client.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strconv"
	"strings"
	"time"

	"github.com/user/uulink/pkg/auth"
)

const defaultBaseURL = "https://api.nrd.nie.163.com"

// Client wraps HTTP calls to the UU Remote REST API.
type Client struct {
	cfg     *auth.Config
	http    *http.Client
	baseURL string
}

// ClientOptions configures transport details, primarily for tests and custom
// deployments. Zero values select the production API and default HTTP client.
type ClientOptions struct {
	BaseURL    string
	HTTPClient *http.Client
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
	return NewClientWithOptions(cfg, ClientOptions{})
}

// NewClientWithOptions creates an API client with injectable transport details.
func NewClientWithOptions(cfg *auth.Config, options ClientOptions) *Client {
	baseURL := strings.TrimRight(options.BaseURL, "/")
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	httpClient := options.HTTPClient
	if httpClient == nil {
		jar, _ := cookiejar.New(nil) // nil options cannot produce an error
		httpClient = &http.Client{Timeout: 60 * time.Second, Jar: jar}
	}
	return &Client{
		cfg:     cfg,
		http:    httpClient,
		baseURL: baseURL,
	}
}

func (c *Client) withConfig(cfg *auth.Config) *Client {
	return NewClientWithOptions(cfg, ClientOptions{BaseURL: c.baseURL, HTTPClient: c.http})
}

// Do sends an authenticated request and returns the parsed JSON response.
func (c *Client) Do(method, path string, body any) (map[string]any, error) {
	return c.DoContext(context.Background(), method, path, body)
}

// DoContext sends an authenticated request using ctx and returns the raw JSON
// response for protocol inspection. Endpoint helpers should expose typed data.
func (c *Client) DoContext(ctx context.Context, method, path string, body any) (map[string]any, error) {
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

	fullURL := c.baseURL + path
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	headers := auth.BuildHeaders(c.cfg, ts)
	sign := auth.Sign(method, fullURL, headers, bodyStr)
	headers["X-Param-SIGN"] = sign

	var bodyReader io.Reader
	if bodyBytes != nil {
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
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

	return decodeJSONResponse(resp, "API request")
}

func decodeJSONResponse(resp *http.Response, operation string) (map[string]any, error) {
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%s: read response: %w", operation, err)
	}
	httpOK := resp.StatusCode >= http.StatusOK && resp.StatusCode < http.StatusMultipleChoices

	// The API reports business failures such as 1002 (object not found) and
	// 1120 (token expired) with HTTP 400 and a normal {code,msg,data} envelope.
	// Decode the envelope first so callers can react to the business code.
	var result map[string]any
	if err := json.Unmarshal(responseBody, &result); err != nil {
		if !httpOK {
			return nil, fmt.Errorf("%s: unexpected HTTP status %d", operation, resp.StatusCode)
		}
		return nil, fmt.Errorf("%s: decode JSON response: %w", operation, err)
	}
	if code, ok := result["code"].(float64); ok && code != 0 {
		message, _ := result["msg"].(string)
		return nil, &ResponseError{Code: int(code), Message: message, Response: result}
	}
	if !httpOK {
		return nil, fmt.Errorf("%s: unexpected HTTP status %d", operation, resp.StatusCode)
	}
	return result, nil
}

func responseData(response map[string]any, operation string) (map[string]any, error) {
	data, ok := response["data"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s response has no data", operation)
	}
	return data, nil
}

// UserInfo is the user data returned for the active login.
type UserInfo struct {
	UserID   string
	Nickname string
	Raw      map[string]any
}

// GetUserInfo fetches current user info.
func (c *Client) GetUserInfo() (*UserInfo, error) {
	response, err := c.Do("GET", "/api/v1/user/info", nil)
	if err != nil {
		return nil, err
	}
	data, err := responseData(response, "user info")
	if err != nil {
		return nil, err
	}
	user := &UserInfo{Raw: data}
	user.UserID, _ = data["user_id"].(string)
	user.Nickname, _ = data["nickname"].(string)
	return user, nil
}

// DeviceInfo is one entry returned by the device-list endpoint.
type DeviceInfo struct {
	DeviceID    string
	Alias       string
	Status      string
	Platform    int
	ClientID    string
	VersionName string
}

// GetDeviceList fetches and normalizes all device-list groups.
func (c *Client) GetDeviceList() ([]DeviceInfo, error) {
	response, err := c.Do("GET", "/api/v1/device/list", nil)
	if err != nil {
		return nil, err
	}
	data, err := responseData(response, "device list")
	if err != nil {
		return nil, err
	}

	var devices []DeviceInfo
	for _, group := range []string{"current_device", "my_binded_devices", "others_shared_devices"} {
		var items []any
		switch value := data[group].(type) {
		case []any:
			items = value
		case map[string]any:
			items = []any{value}
		}
		for _, item := range items {
			raw, ok := item.(map[string]any)
			if !ok {
				continue
			}
			device := DeviceInfo{}
			device.DeviceID, _ = raw["device_id"].(string)
			device.Alias, _ = raw["alias"].(string)
			device.Status, _ = raw["status"].(string)
			if platform, ok := raw["platform"].(float64); ok {
				device.Platform = int(platform)
			}
			device.ClientID, _ = raw["client_id"].(string)
			device.VersionName, _ = raw["version_name"].(string)
			devices = append(devices, device)
		}
	}
	return devices, nil
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
