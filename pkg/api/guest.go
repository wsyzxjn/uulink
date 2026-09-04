package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const sharePassCodeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// GuestSession holds the temporary identity returned by /guest/create.
type GuestSession struct {
	GuestID  string
	Token    string
	UserID   string
	DeviceID string
	ClientID string
}

// CreateGuest requests a guest identity without using the configured JWT.
func (c *Client) CreateGuest() (*GuestSession, error) {
	cfg := *c.cfg
	cfg.JWT = ""
	cfg.UserID = ""
	cfg.GuestID = ""

	resp, err := c.withConfig(&cfg).Do("POST", "/api/v1/guest/create", map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("guest create: %w", err)
	}
	data, err := responseData(resp, "guest create")
	if err != nil {
		return nil, err
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

	return &GuestSession{GuestID: guestID, Token: token, UserID: userID, DeviceID: deviceID, ClientID: cfg.ClientID}, nil
}

// CreateUnboundGuest registers a new device without a user account and then
// creates a guest session for it. The resulting session is not associated
// with any logged-in user, which avoids the server's same-account
// self-assist restriction.
func (c *Client) CreateUnboundGuest(name string) (*GuestSession, *UnboundDeviceIdentity, error) {
	identity, err := c.InitWindowsDeviceWithoutAuth(name)
	if err != nil {
		return nil, nil, fmt.Errorf("create unbound device: %w", err)
	}

	cfg := *c.cfg
	cfg.JWT = ""
	cfg.UserID = ""
	cfg.GuestID = ""
	cfg.ClientID = identity.ClientID
	cfg.DeviceID = identity.DeviceID
	cfg.Platform = 1
	session, err := c.withConfig(&cfg).CreateGuest()
	if err != nil {
		return nil, identity, fmt.Errorf("create guest for unbound device: %w", err)
	}
	session.ClientID = identity.ClientID
	return session, identity, nil
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
	if session.ClientID != "" {
		cfg.ClientID = session.ClientID
		if strings.HasPrefix(session.ClientID, "MG-") {
			cfg.Platform = 1
		}
	}
	return c.withConfig(&cfg)
}

// CreateGuestRoom calls POST /api/v1/guest/room/create with a guest session.
func (c *Client) CreateGuestRoom(session *GuestSession) (*RoomConnectionInfo, error) {
	resp, err := c.guestClient(session).Do("POST", "/api/v1/guest/room/create", map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("guest room create: %w", err)
	}
	data, err := responseData(resp, "guest room create")
	if err != nil {
		return nil, err
	}
	return parseRoomConnectionInfo(data), nil
}

// GuestShareInfo holds the temporary share code returned to a guest.
type GuestShareInfo struct {
	Alias         string
	ConnectID     string
	ConnectCode   string
	TemporaryCode string
	CustomCode    string
	ControlID     string
	Raw           map[string]any
}

// GetGuestShareInfo calls POST /api/v1/guest/share/info with a guest session.
func (c *Client) GetGuestShareInfo(session *GuestSession) (*GuestShareInfo, error) {
	resp, err := c.guestClient(session).Do("POST", "/api/v1/guest/share/info", map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("guest share info: %w", err)
	}
	data, err := responseData(resp, "guest share info")
	if err != nil {
		return nil, err
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

// GenerateCustomShareCode creates an eight-character code that satisfies the
// official custom-code rule of containing both letters and digits.
func GenerateCustomShareCode() (string, error) {
	for attempt := 0; attempt < 32; attempt++ {
		code, err := GenerateSharePassCode()
		if err != nil {
			return "", err
		}
		hasLetter := false
		hasDigit := false
		for _, char := range code {
			if char >= '0' && char <= '9' {
				hasDigit = true
			} else {
				hasLetter = true
			}
		}
		if hasLetter && hasDigit {
			return code, nil
		}
	}
	return "", errors.New("generate custom share code: unable to satisfy code alphabet")
}

// ValidateCustomShareCode enforces the official custom-code format.
func ValidateCustomShareCode(code string) error {
	if len(code) < 8 || len(code) > 16 {
		return fmt.Errorf("custom share code length is %d, want 8-16", len(code))
	}
	hasLetter := false
	hasDigit := false
	for _, char := range code {
		switch {
		case char >= '0' && char <= '9':
			hasDigit = true
		case char >= 'a' && char <= 'z', char >= 'A' && char <= 'Z':
			hasLetter = true
		default:
			return fmt.Errorf("custom share code contains invalid character %q", char)
		}
	}
	if !hasLetter || !hasDigit {
		return errors.New("custom share code must contain both letters and digits")
	}
	return nil
}

// SharePassCodeSign returns the lowercase SHA-256 hex digest used by the guest
// share upload-sign endpoint for the pass code without push salt.
func SharePassCodeSign(passCode string) string {
	digest := sha256.Sum256([]byte(passCode))
	return hex.EncodeToString(digest[:])
}

// SharePassCodeSignWithSalt returns the SHA-256 digest that incorporates the
// server-provided salt from the remote-control push. As verified from official
// client disassembly, controlID is passed separately in the JSON body, and the
// signature is SHA256(salt + passCode).
func SharePassCodeSignWithSalt(salt, passCode string) string {
	digest := sha256.Sum256([]byte(salt + passCode))
	return hex.EncodeToString(digest[:])
}

// ShareAuthMode selects the official guest share authorization mode.
type ShareAuthMode string

const (
	// ShareAuthTemporary maps to the official by_password control mode and
	// requires the generated temporary verification code.
	ShareAuthTemporary ShareAuthMode = "temporary"
	// ShareAuthCustom maps to the official by_confirmation control mode and
	// requires a caller-selected custom verification code.
	ShareAuthCustom ShareAuthMode = "custom"
	// ShareAuthBoth maps to the official password_confirmation control mode
	// and requires both the temporary and custom verification codes.
	ShareAuthBoth ShareAuthMode = "both"
)

// ParseShareAuthMode converts the CLI mode name to a ShareAuthMode.
func ParseShareAuthMode(value string) (ShareAuthMode, error) {
	switch value {
	case "temporary":
		return ShareAuthTemporary, nil
	case "custom":
		return ShareAuthCustom, nil
	case "both":
		return ShareAuthBoth, nil
	default:
		return "", fmt.Errorf("invalid share auth mode %q (want temporary, custom, or both)", value)
	}
}

// OfficialControlMode returns the control_mode string used by the official
// API. Temporary and custom codes are both password modes; a custom code only
// changes which code is signed, not whether the controller must be confirmed.
func (mode ShareAuthMode) OfficialControlMode() string {
	switch mode {
	case ShareAuthTemporary, ShareAuthCustom:
		return "by_password"
	case ShareAuthBoth:
		return "password_confirmation"
	default:
		return ""
	}
}

// NeedsConfirmation returns the need_confirmation value used with the mode.
func (mode ShareAuthMode) NeedsConfirmation() bool {
	return mode == ShareAuthBoth
}

// ShareJoinCode returns the verification string submitted by the controller.
func ShareJoinCode(temporaryCode, customCode string, mode ShareAuthMode) string {
	switch mode {
	case ShareAuthTemporary:
		return temporaryCode
	case ShareAuthCustom:
		return customCode
	case ShareAuthBoth:
		return temporaryCode + customCode
	default:
		return ""
	}
}

// GuestShareUploadSignRequest is the request body for the recipient-side
// verification-code upload.
type GuestShareUploadSignRequest struct {
	CanControl       bool   `json:"can_remote_control"`
	ControlID        string `json:"control_id"`
	Sign             string `json:"sign"`
	BackupSign       string `json:"backup_sign"`
	ControlMode      string `json:"control_mode"`
	NeedConfirmation bool   `json:"need_confirmation"`
}

// NewGuestShareUploadSignRequest builds the official upload-sign body for a
// share authorization mode. The temporary code is signed in sign and the
// custom code is signed in backup_sign.
func NewGuestShareUploadSignRequest(controlID, temporaryCode, customCode string, mode ShareAuthMode) *GuestShareUploadSignRequest {
	return NewGuestShareUploadSignRequestWithSalt(controlID, "", temporaryCode, customCode, mode)
}

// NewGuestShareUploadSignRequestWithSalt builds the upload-sign body using
// the salted digest from the remote-control push. As verified from official
// client disassembly, controlID is passed separately in the JSON body, and the
// signature is SHA256(salt + passCode).
func NewGuestShareUploadSignRequestWithSalt(controlID, salt, temporaryCode, customCode string, mode ShareAuthMode) *GuestShareUploadSignRequest {
	request := &GuestShareUploadSignRequest{
		CanControl:       true,
		ControlID:        controlID,
		ControlMode:      mode.OfficialControlMode(),
		NeedConfirmation: mode.NeedsConfirmation(),
	}
	switch mode {
	case ShareAuthTemporary:
		request.Sign = SharePassCodeSignWithSalt(salt, temporaryCode)
	case ShareAuthCustom:
		request.Sign = SharePassCodeSignWithSalt(salt, customCode)
		request.BackupSign = request.Sign
	case ShareAuthBoth:
		request.Sign = SharePassCodeSignWithSalt(salt, temporaryCode)
		request.BackupSign = SharePassCodeSignWithSalt(salt, customCode)
	}
	return request
}

// GuestShareUploadControlModeRequest is the request body used by a guest
// controlled endpoint to publish its remote-assistance control mode.
type GuestShareUploadControlModeRequest struct {
	ControlID    string `json:"control_id"`
	AllowControl bool   `json:"allow_control"`
	ControlMode  string `json:"control_mode"`
}

// NewGuestShareUploadControlModeRequest builds a control-mode upload request.
func NewGuestShareUploadControlModeRequest(controlID string, allowControl bool, mode ShareAuthMode) *GuestShareUploadControlModeRequest {
	return &GuestShareUploadControlModeRequest{
		ControlID:    controlID,
		AllowControl: allowControl,
		ControlMode:  mode.OfficialControlMode(),
	}
}

// GuestShareConfirmationRequest is the request body used by a guest
// controlled endpoint to accept a remote-control confirmation push.
type GuestShareConfirmationRequest struct {
	ControlID    string `json:"control_id"`
	AllowControl bool   `json:"allow_control"`
	NeedPassword bool   `json:"need_password"`
}

// GuestShareUploadSign publishes the verification-code signature. The v2
// endpoint matches the controller's v2 join; the v1 endpoint remains as a
// fallback for guest sessions the v2 endpoint rejects.
func (c *Client) GuestShareUploadSign(session *GuestSession, request *GuestShareUploadSignRequest) (map[string]any, error) {
	if resp, err := c.GuestShareUploadSignV2(session, request); err == nil {
		return resp, nil
	}
	resp, err := c.guestClient(session).Do("POST", "/api/v1/guest/room/share/upload/sign", request)
	if err != nil {
		return nil, fmt.Errorf("guest share upload sign: %w", err)
	}
	return resp, nil
}

// GuestShareUploadSignV2 calls POST /api/v2/room/share/upload_sign. The
// official controller join also uses v2 endpoints, so the guest-side sign
// upload must use the same API generation for the server to associate them.
func (c *Client) GuestShareUploadSignV2(session *GuestSession, request *GuestShareUploadSignRequest) (map[string]any, error) {
	resp, err := c.guestClient(session).Do("POST", "/api/v2/room/share/upload_sign", request)
	if err != nil {
		return nil, fmt.Errorf("guest share upload sign v2: %w", err)
	}
	return resp, nil
}

// GuestShareUploadControlMode publishes the control mode, preferring the v2
// endpoint and falling back to v1 like GuestShareUploadSign.
func (c *Client) GuestShareUploadControlMode(session *GuestSession, request *GuestShareUploadControlModeRequest) (map[string]any, error) {
	if resp, err := c.GuestShareUploadControlModeV2(session, request); err == nil {
		return resp, nil
	}
	resp, err := c.guestClient(session).Do("POST", "/api/v1/guest/room/share/upload_control_mode", request)
	if err != nil {
		return nil, fmt.Errorf("guest share upload control mode: %w", err)
	}
	return resp, nil
}

// GuestShareUploadControlModeV2 calls POST /api/v2/room/share/upload_control_mode.
func (c *Client) GuestShareUploadControlModeV2(session *GuestSession, request *GuestShareUploadControlModeRequest) (map[string]any, error) {
	resp, err := c.guestClient(session).Do("POST", "/api/v2/room/share/upload_control_mode", request)
	if err != nil {
		return nil, fmt.Errorf("guest share upload control mode v2: %w", err)
	}
	return resp, nil
}

// GuestSetDeviceControllable marks a guest-controlled device as available for
// remote assistance.
func (c *Client) GuestSetDeviceControllable(session *GuestSession, controllable bool) (map[string]any, error) {
	resp, err := c.guestClient(session).Do("POST", "/api/v1/device/controllable", map[string]bool{
		"controllable": controllable,
	})
	if err != nil {
		return nil, fmt.Errorf("guest set device controllable: %w", err)
	}
	return resp, nil
}

// GetShareControlMode queries the controller-side remote-assistance control
// mode for a share.
func (c *Client) GetShareControlMode(connectID string) (map[string]any, error) {
	resp, err := c.Do("POST", "/api/v2/room/share/control_mode", map[string]string{
		"connect_id": connectID,
	})
	if err != nil {
		return nil, fmt.Errorf("get share control mode: %w", err)
	}
	return resp, nil
}

// GuestShareConfirmation calls the guest-side confirmation endpoint. It must
// be sent after the controlling side triggers the remote_control push.
func (c *Client) GuestShareConfirmation(session *GuestSession, request *GuestShareConfirmationRequest) (map[string]any, error) {
	resp, err := c.guestClient(session).Do("POST", "/api/v1/guest/room/share/confirmation", request)
	if err != nil {
		return nil, fmt.Errorf("guest share confirmation: %w", err)
	}
	return resp, nil
}

// JoinRoomByShareCodeRequest is the official v2 by_code request body.
type JoinRoomByShareCodeRequest struct {
	ConnectID   string `json:"connect_id"`
	ConnectCode string `json:"connect_code"`
}

// codeAwaitingConfirmation is returned by the by_code join while the
// controlled side has not yet confirmed the controller.
const codeAwaitingConfirmation = 1136

const joinConfirmationAttempts = 20

// joinConfirmationInterval is a variable so tests can shorten the wait.
var joinConfirmationInterval = time.Second

// joinShareRoomByCode posts the v2 by_code join with the given client and
// keeps polling while the server reports that the controlled side still has
// to confirm the controller.
func joinShareRoomByCode(client *Client, connectID, deviceCode, operation string) (*RoomConnectionInfo, error) {
	body := &JoinRoomByShareCodeRequest{
		ConnectID:   connectID,
		ConnectCode: deviceCode,
	}
	for attempt := 0; attempt < joinConfirmationAttempts; attempt++ {
		resp, err := client.Do("POST", "/api/v2/room/join/share/by_code", body)
		if err != nil {
			var responseErr *ResponseError
			if errors.As(err, &responseErr) && responseErr.Code == codeAwaitingConfirmation {
				time.Sleep(joinConfirmationInterval)
				continue
			}
			return nil, fmt.Errorf("%s: %w", operation, err)
		}
		data, err := responseData(resp, operation)
		if err != nil {
			return nil, err
		}
		return parseRoomConnectionInfo(data), nil
	}
	return nil, fmt.Errorf("%s: timed out waiting for remote control confirmation", operation)
}

// JoinRoomByShareCode calls POST /api/v2/room/join/share/by_code with a
// logged-in controller identity, waiting for the controlled side's
// confirmation when the share requires one.
func (c *Client) JoinRoomByShareCode(connectID, deviceCode string) (*RoomConnectionInfo, error) {
	return joinShareRoomByCode(c, connectID, deviceCode, "join share room")
}

// JoinRoomByShareCodeWithGuest joins a remote-assistance share using a guest
// identity instead of the configured user JWT.
func (c *Client) JoinRoomByShareCodeWithGuest(session *GuestSession, connectID, deviceCode string) (*RoomConnectionInfo, error) {
	return joinShareRoomByCode(c.guestClient(session), connectID, deviceCode, "join share room with guest")
}

// JoinRoomByConfirmation starts the v2 remote-assistance confirmation flow.
// The controlling side must be logged in; controlId identifies the controller.
func (c *Client) JoinRoomByConfirmation(connectID, controlID string) (*RoomConnectionInfo, error) {
	body := map[string]any{
		"connect_id": connectID,
		"control_id": controlID,
	}
	resp, err := c.Do("POST", "/api/v2/room/join/share/by_confirmation", body)
	if err != nil {
		return nil, fmt.Errorf("join room by confirmation: %w", err)
	}
	data, err := responseData(resp, "join room by confirmation")
	if err != nil {
		return nil, err
	}
	return parseRoomConnectionInfo(data), nil
}

// JoinRoomByConfirmationWithGuest starts the v2 remote-assistance
// confirmation flow using a guest controller identity.
func (c *Client) JoinRoomByConfirmationWithGuest(session *GuestSession, connectID, controlID string) (*RoomConnectionInfo, error) {
	body := map[string]any{
		"connect_id": connectID,
		"control_id": controlID,
	}
	resp, err := c.guestClient(session).Do("POST", "/api/v2/room/join/share/by_confirmation", body)
	if err != nil {
		return nil, fmt.Errorf("join room by confirmation with guest: %w", err)
	}
	data, err := responseData(resp, "join room by confirmation with guest")
	if err != nil {
		return nil, err
	}
	return parseRoomConnectionInfo(data), nil
}
