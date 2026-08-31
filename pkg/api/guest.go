package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

const sharePassCodeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// GuestSession holds the temporary identity returned by /guest/create.
type GuestSession struct {
	GuestID  string
	Token    string
	UserID   string
	DeviceID string
}

// CreateGuest requests a guest identity without using the configured JWT.
func (c *Client) CreateGuest() (*GuestSession, error) {
	cfg := *c.cfg
	cfg.JWT = ""
	cfg.UserID = ""
	cfg.GuestID = ""

	resp, err := NewClient(&cfg).Do("POST", "/api/v1/guest/create", map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("guest create: %w", err)
	}
	if code, ok := resp["code"].(float64); ok && code != 0 {
		return nil, fmt.Errorf("guest create failed, code %v: %v", code, resp["msg"])
	}

	data, ok := resp["data"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("guest create response has no data: %v", resp)
	}
	guestID, _ := data["guest_id"].(string)
	token, _ := data["token"].(string)
	if guestID == "" || token == "" {
		return nil, fmt.Errorf("guest create response missing guest_id or token")
	}

	userID, deviceID, err := jwtClaims(token)
	if err != nil {
		return nil, fmt.Errorf("decode guest token: %w", err)
	}

	return &GuestSession{GuestID: guestID, Token: token, UserID: userID, DeviceID: deviceID}, nil
}

func jwtClaims(token string) (userID string, deviceID string, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", "", fmt.Errorf("token has %d segments, want 3", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", err
	}
	var claims struct {
		Sub      string `json:"sub"`
		DeviceID string `json:"device_id"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", "", err
	}
	if claims.Sub == "" {
		return "", "", fmt.Errorf("token has no subject")
	}
	return claims.Sub, claims.DeviceID, nil
}

func (c *Client) guestClient(session *GuestSession) *Client {
	cfg := *c.cfg
	cfg.JWT = session.Token
	cfg.UserID = session.UserID
	cfg.GuestID = session.GuestID
	if session.DeviceID != "" {
		cfg.DeviceID = session.DeviceID
	}
	return NewClient(&cfg)
}

// CreateGuestRoom calls POST /api/v1/guest/room/create with a guest session.
func (c *Client) CreateGuestRoom(session *GuestSession) (*RoomConnectionInfo, error) {
	resp, err := c.guestClient(session).Do("POST", "/api/v1/guest/room/create", map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("guest room create: %w", err)
	}
	if code, ok := resp["code"].(float64); ok && code != 0 {
		return nil, fmt.Errorf("guest room create failed, code %v: %v", code, resp["msg"])
	}
	data, ok := resp["data"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("guest room create response has no data: %v", resp)
	}
	return parseRoomConnectionInfo(data), nil
}

// GuestShareInfo holds the temporary share code returned to a guest.
type GuestShareInfo struct {
	Alias       string
	ConnectID   string
	ConnectCode string
	Raw         map[string]any
}

// GetGuestShareInfo calls POST /api/v1/guest/share/info with a guest session.
func (c *Client) GetGuestShareInfo(session *GuestSession) (*GuestShareInfo, error) {
	resp, err := c.guestClient(session).Do("POST", "/api/v1/guest/share/info", map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("guest share info: %w", err)
	}
	if code, ok := resp["code"].(float64); ok && code != 0 {
		return nil, fmt.Errorf("guest share info failed, code %v: %v", code, resp["msg"])
	}
	data, ok := resp["data"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("guest share info response has no data: %v", resp)
	}

	info := &GuestShareInfo{Raw: data}
	info.Alias, _ = data["alias"].(string)
	info.ConnectID, _ = data["connect_id"].(string)
	info.ConnectCode, _ = data["connect_code"].(string)
	return info, nil
}

// GenerateSharePassCode creates the eight-character verification code used by
// the UU Remote recipient flow. The alphabet omits I, O, 0, and 1.
func GenerateSharePassCode() (string, error) {
	out := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, out); err != nil {
		return "", fmt.Errorf("generate share pass code: %w", err)
	}
	for i, b := range out {
		out[i] = sharePassCodeAlphabet[int(b)%len(sharePassCodeAlphabet)]
	}
	return string(out), nil
}

// SharePassCodeSign returns the lowercase SHA-256 hex digest used by the guest
// share upload-sign endpoint.
func SharePassCodeSign(controlID, passCode string) string {
	digest := sha256.Sum256([]byte(controlID + passCode))
	return hex.EncodeToString(digest[:])
}

// GuestShareUploadSignRequest is the request body for the recipient-side
// verification-code upload.
type GuestShareUploadSignRequest struct {
	CanControl bool   `json:"can_control"`
	ControlID  string `json:"control_id"`
	Sign       string `json:"sign"`
	BackupSign string `json:"backup_sign"`
}

// GuestShareUploadSign calls POST /api/v1/guest/room/share/upload/sign.
func (c *Client) GuestShareUploadSign(session *GuestSession, request *GuestShareUploadSignRequest) (map[string]any, error) {
	resp, err := c.guestClient(session).Do("POST", "/api/v1/guest/room/share/upload/sign", request)
	if err != nil {
		return nil, fmt.Errorf("guest share upload sign: %w", err)
	}
	if code, ok := resp["code"].(float64); ok && code != 0 {
		return nil, fmt.Errorf("guest share upload sign failed, code %v: %v", code, resp["msg"])
	}
	return resp, nil
}

// JoinRoomByShareCode calls POST /api/v1/room/join/share/by_code with a
// logged-in controller identity.
func (c *Client) JoinRoomByShareCode(connectID, deviceCode string) (*RoomConnectionInfo, error) {
	body := map[string]any{
		"connect_id":  connectID,
		"device_code": deviceCode,
	}
	resp, err := c.Do("POST", "/api/v1/room/join/share/by_code", body)
	if err != nil {
		return nil, fmt.Errorf("join share room: %w", err)
	}
	if code, ok := resp["code"].(float64); ok && code != 0 {
		return nil, fmt.Errorf("join share room failed, code %v: %v", code, resp["msg"])
	}
	data, ok := resp["data"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("join share room response has no data: %v", resp)
	}
	return parseRoomConnectionInfo(data), nil
}

// JoinRoomByShareCodeWithGuest joins a remote-assistance share using a guest
// identity instead of the configured user JWT.
func (c *Client) JoinRoomByShareCodeWithGuest(session *GuestSession, connectID, deviceCode string) (*RoomConnectionInfo, error) {
	body := map[string]any{
		"connect_id":  connectID,
		"device_code": deviceCode,
	}
	resp, err := c.guestClient(session).Do("POST", "/api/v1/room/join/share/by_code", body)
	if err != nil {
		return nil, fmt.Errorf("join share room with guest: %w", err)
	}
	if code, ok := resp["code"].(float64); ok && code != 0 {
		return nil, fmt.Errorf("join share room with guest failed, code %v: %v", code, resp["msg"])
	}
	data, ok := resp["data"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("join share room with guest response has no data: %v", resp)
	}
	return parseRoomConnectionInfo(data), nil
}
