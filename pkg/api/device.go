package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/wsyzxjn/uulink/pkg/auth"
)

// DeviceIdentity is the registered identity and its upstream platform.
// Guest sessions carry the platform explicitly instead of inferring it from IDs.
type DeviceIdentity struct {
	ClientID string
	DeviceID string
	Platform int
}

// pseudoMAC derives a stable, locally administered MAC address from the
// client ID. The device registration endpoints expect a MAC, but the real
// hardware address of this machine is nobody's business, and one fixed value
// shared by every installation would make all of them look like one device.
func pseudoMAC(clientID string) string {
	digest := sha256.Sum256([]byte("uulink-mac:" + clientID))
	b := digest[:6]
	b[0] = (b[0] | 0x02) &^ 0x01 // locally administered, unicast
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

// InitDeviceContext registers a device using the selected platform. Successful
// registration updates the active identity; errors leave it unchanged.
func (c *Client) InitDeviceContext(ctx context.Context, name string) (*DeviceIdentity, error) {
	cfg := *c.cfg
	platform := cfg.Identity().Platform
	clientID, err := registrationClientID(cfg.ClientID, platform)
	if err != nil {
		return nil, err
	}
	if clientID != cfg.ClientID {
		cfg.DeviceID = ""
	}
	cfg.ClientID, cfg.Platform = clientID, platform
	identity, err := c.withConfig(&cfg).registerDeviceContext(ctx, name)
	if err != nil {
		return nil, err
	}
	c.cfg.ClientID, c.cfg.DeviceID, c.cfg.Platform = identity.ClientID, identity.DeviceID, identity.Platform
	return identity, nil
}

// InitDeviceWithoutAuthContext keeps unbound and logged-in identities separate.
// An explicit platform change creates a new identity rather than registering a
// Windows ID through the macOS endpoint (or the reverse).
func (c *Client) InitDeviceWithoutAuthContext(ctx context.Context, name string) (*DeviceIdentity, error) {
	cfg := *c.cfg
	platform := cfg.Identity().Platform
	clientID := cfg.UnboundClientID
	previousPlatform := cfg.UnboundPlatform
	if previousPlatform == 0 && clientID != "" {
		previousPlatform = auth.MacPlatform
		if strings.HasPrefix(clientID, "MG-") {
			previousPlatform = auth.WindowsPlatform
		}
	}
	if previousPlatform != 0 && previousPlatform != platform {
		clientID = ""
	}
	clientID, err := registrationClientID(clientID, platform)
	if err != nil {
		return nil, err
	}
	cfg.JWT, cfg.UserID, cfg.GuestID, cfg.DeviceID = "", "", "", ""
	cfg.ClientID, cfg.Platform = clientID, platform
	identity, err := c.withConfig(&cfg).registerDeviceContext(ctx, name)
	if err != nil {
		return nil, err
	}
	c.cfg.UnboundClientID, c.cfg.UnboundDeviceID, c.cfg.UnboundPlatform = identity.ClientID, identity.DeviceID, identity.Platform
	return identity, nil
}

func registrationClientID(previous string, platform int) (string, error) {
	if platform != auth.WindowsPlatform && platform != auth.MacPlatform {
		return "", fmt.Errorf("unsupported registration platform %d", platform)
	}
	windowsID := strings.HasPrefix(previous, "MG-")
	if previous != "" && windowsID == (platform == auth.WindowsPlatform) {
		if windowsID {
			return "MG-" + strings.ToLower(strings.TrimPrefix(previous, "MG-")), nil
		}
		return previous, nil
	}
	id, err := uuid.NewRandom()
	if err != nil {
		return "", fmt.Errorf("generate device uuid: %w", err)
	}
	if platform == auth.WindowsPlatform {
		return "MG-" + id.String(), nil
	}
	return strings.ToUpper(id.String()), nil
}

func (c *Client) registerDeviceContext(ctx context.Context, name string) (*DeviceIdentity, error) {
	platform := c.cfg.Identity().Platform
	var path string
	switch platform {
	case auth.WindowsPlatform:
		path = "/api/v1/device/windows/init"
	case auth.MacPlatform:
		path = "/api/v1/device/macos/init"
	default:
		return nil, fmt.Errorf("unsupported registration platform %d", platform)
	}
	body := c.cfg.Devices.RegistrationMetadata(platform)
	body["client_id"], body["system_id"] = c.cfg.ClientID, c.cfg.ClientID
	body["name"], body["mac"], body["controllable"] = name, pseudoMAC(c.cfg.ClientID), true
	if platform == auth.WindowsPlatform {
		guid := strings.TrimPrefix(c.cfg.ClientID, "MG-")
		body["machine_guid"], body["guid"] = guid, guid
	}
	resp, err := c.DoContext(ctx, "POST", path, body)
	if err != nil {
		return nil, fmt.Errorf("register device (platform %d): %w", platform, err)
	}
	data, err := responseData(resp, "init device")
	if err != nil {
		return nil, err
	}
	deviceID, _ := data["device_id"].(string)
	if deviceID == "" {
		return nil, fmt.Errorf("init device response missing device_id")
	}
	return &DeviceIdentity{ClientID: c.cfg.ClientID, DeviceID: deviceID, Platform: platform}, nil
}

// SetDeviceControllableContext selects the same platform as registration and
// authentication, including when called through a guest-scoped client.
func (c *Client) SetDeviceControllableContext(ctx context.Context, controllable bool) (map[string]any, error) {
	var path string
	switch c.cfg.Identity().Platform {
	case auth.WindowsPlatform:
		path = "/api/v1/device/controllable"
	case auth.MacPlatform:
		path = "/api/v1/device/mac_controllable"
	default:
		return nil, fmt.Errorf("unsupported controllable platform")
	}
	resp, err := c.DoContext(ctx, "POST", path, map[string]bool{"controllable": controllable})
	if err != nil {
		return nil, fmt.Errorf("set device controllable: %w", err)
	}
	return resp, nil
}

// ReportIP performs the controlled client's relay IP report.
func (c *Client) ReportIP(room *RoomConnectionInfo) (map[string]any, error) {
	return c.ReportIPContext(context.Background(), room)
}

// ReportIPContext performs the controlled client's relay IP report using ctx.
func (c *Client) ReportIPContext(ctx context.Context, room *RoomConnectionInfo) (map[string]any, error) {
	return c.reportRequest(ctx, http.MethodGet, room.ReportURL, "/api/v1/ip", room.ReportToken, nil)
}

// ReportEchoServers performs the controlled client's relay echo-server report.
func (c *Client) ReportEchoServers(room *RoomConnectionInfo) (map[string]any, error) {
	return c.ReportEchoServersContext(context.Background(), room)
}

// ReportEchoServersContext performs the relay echo-server report using ctx.
func (c *Client) ReportEchoServersContext(ctx context.Context, room *RoomConnectionInfo) (map[string]any, error) {
	return c.reportRequest(ctx, http.MethodGet, room.ReportURL, "/api/v1/echo_server", room.ReportToken, nil)
}

func (c *Client) reportRequest(ctx context.Context, method, baseURL, path, reportToken string, body any) (map[string]any, error) {
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
		"x-param-sv":     c.cfg.Identity().StreamerVersion,
	}
	headers["x-param-sign"] = auth.SignWithKey(c.cfg.Identity().SigningKey, method, fullURL, headers, bodyStr)

	var bodyReader io.Reader
	if bodyBytes != nil {
		bodyReader = bytes.NewReader(bodyBytes)
		headers["Content-Type"] = "application/json"
	}
	requestCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, method, fullURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("new report request: %w", err)
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	req.Header.Set("Content-Length", strconv.Itoa(len(bodyBytes)))

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("report http do: %w", err)
	}
	defer resp.Body.Close()
	return decodeJSONResponse(resp, "report request")
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}
