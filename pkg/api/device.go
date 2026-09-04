package api

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/user/uulink/pkg/auth"
)

// UnboundDeviceIdentity holds a device identity that is registered on the
// server without being associated with any user account. The guest share flow
// accepts these identities, which avoids the same-account self-assist block.
type UnboundDeviceIdentity struct {
	ClientID string
	DeviceID string
}

// InitMacDevice registers this Mac as a controlled device. The body mirrors
// the official macOS client's /device/macos/init request; values that identify
// this installation are taken from the auth config.
func (c *Client) InitMacDevice(name string) (map[string]any, error) {
	body := map[string]any{
		"client_id":        c.cfg.ClientID,
		"os":               "版本27.0（版号26A5421a）",
		"resolution":       "2560x1440",
		"system_name":      "macOS",
		"memory":           "16384",
		"model_number":     "MU9D3CH/A",
		"controllable":     true,
		"name":             name,
		"model":            "Mac",
		"cpu":              "Apple M4",
		"mac":              "d0:11:e5:d5:b9:95",
		"video":            []string{"Apple M4"},
		"system_id":        c.cfg.ClientID,
		"model_identifier": "Mac16,10",
		"system_version":   "27.0.0",
		"dpi":              144,
	}
	resp, err := c.Do("POST", "/api/v1/device/macos/init", body)
	if err != nil {
		return nil, fmt.Errorf("init mac device: %w", err)
	}
	if code, ok := resp["code"].(float64); ok && code != 0 {
		return nil, fmt.Errorf("init mac device failed, code %v: %v", code, resp["msg"])
	}
	return resp, nil
}

// InitWindowsDeviceWithoutAuth registers a Windows-shaped device on the
// server without a user JWT. The returned device is not bound to any user
// account, which makes it usable as an anonymous guest-controlled endpoint.
func (c *Client) InitWindowsDeviceWithoutAuth(name string) (*UnboundDeviceIdentity, error) {
	guid := ""
	if c.cfg != nil && c.cfg.ClientID != "" {
		guid = strings.ToLower(strings.TrimPrefix(c.cfg.ClientID, "MG-"))
	}
	if guid == "" {
		id, err := uuid.NewRandom()
		if err != nil {
			return nil, fmt.Errorf("generate device uuid: %w", err)
		}
		guid = id.String()
		if c.cfg != nil {
			c.cfg.ClientID = strings.ToUpper(guid)
		}
	}
	clientID := "MG-" + guid

	body := map[string]any{
		"name":         name,
		"client_id":    clientID,
		"system_id":    clientID,
		"machine_guid": guid,
		"guid":         guid,
		"os":           "Microsoft Windows NT 10.0.26200.0",
		"base_board":   "Virtual",
		"cpu":          "Virtual CPU",
		"video":        []string{"Virtual GPU"},
		"mac":          "00:11:22:33:44:55",
		"memory":       "16384",
		"screen":       "1920x1080",
		"controllable": true,
		"platform":     1,
	}

	cfg := *c.cfg
	cfg.JWT = ""
	cfg.UserID = ""
	cfg.GuestID = ""
	cfg.ClientID = clientID
	cfg.DeviceID = ""
	cfg.Platform = 1
	subClient := NewClient(&cfg)
	subClient.http.Transport = c.http.Transport
	resp, err := subClient.Do("POST", "/api/v1/device/windows/init", body)
	if err != nil {
		return nil, fmt.Errorf("init windows device without auth: %w", err)
	}
	if code, ok := resp["code"].(float64); ok && code != 0 {
		message, _ := resp["msg"].(string)
		return nil, &ResponseError{Code: int(code), Message: message, Response: resp}
	}

	data, ok := resp["data"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("init windows device response has no data: %v", resp)
	}
	deviceID, _ := data["device_id"].(string)
	if deviceID == "" {
		return nil, fmt.Errorf("init windows device response missing device_id")
	}
	if c.cfg != nil && c.cfg.DeviceID == "" {
		c.cfg.DeviceID = deviceID
	}

	return &UnboundDeviceIdentity{ClientID: clientID, DeviceID: deviceID}, nil
}

// SetMacControllable marks the registered Mac as available for control.
func (c *Client) SetMacControllable(controllable bool) (map[string]any, error) {
	resp, err := c.Do("POST", "/api/v1/device/mac_controllable", map[string]bool{
		"controllable": controllable,
	})
	if err != nil {
		return nil, fmt.Errorf("set mac controllable: %w", err)
	}
	if code, ok := resp["code"].(float64); ok && code != 0 {
		return nil, fmt.Errorf("set mac controllable failed, code %v: %v", code, resp["msg"])
	}
	return resp, nil
}

// ReportIP performs the controlled client's relay IP report.
func (c *Client) ReportIP(room *RoomConnectionInfo) (map[string]any, error) {
	return c.reportRequest("GET", room.ReportURL, "/api/v1/ip", room.ReportToken, nil)
}

// ReportEchoServers performs the controlled client's relay echo-server report.
func (c *Client) ReportEchoServers(room *RoomConnectionInfo) (map[string]any, error) {
	return c.reportRequest("GET", room.ReportURL, "/api/v1/echo_server", room.ReportToken, nil)
}

func (c *Client) reportRequest(method, baseURL, path, reportToken string, body any) (map[string]any, error) {
	var bodyBytes []byte
	var bodyStr string
	if body != nil {
		var err error
		bodyBytes, err = json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal report body: %w", err)
		}
		bodyStr = string(bodyBytes)
	}

	fullURL := baseURL + path
	nonce, err := randomHex(16)
	if err != nil {
		return nil, fmt.Errorf("report nonce: %w", err)
	}
	headers := map[string]string{
		"Accept":         "*/*",
		"Connection":     "close",
		"x-report-token": reportToken,
		"x-param-nonce":  nonce,
		"x-param-sv":     "V4.5.3",
	}
	headers["x-param-sign"] = auth.Sign(method, fullURL, headers, bodyStr)

	var bodyReader io.Reader
	if bodyBytes != nil {
		bodyReader = bytes.NewReader(bodyBytes)
		headers["Content-Type"] = "application/json"
	}
	req, err := http.NewRequest(method, fullURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("new report request: %w", err)
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	req.Header.Set("Content-Length", strconv.Itoa(len(bodyBytes)))

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("report http do: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read report response: %w", err)
	}
	var result map[string]any
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("report status %d, unmarshal: %w", resp.StatusCode, err)
	}
	return result, nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}
