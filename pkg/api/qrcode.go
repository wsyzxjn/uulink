package api

import (
	"context"
	"fmt"
)

// QRCodeLoginInfo holds the credentials returned by the QR-code login
// bootstrap endpoint.
type QRCodeLoginInfo struct {
	Token             string
	StatusQueryTicket string
	QRCodeJumpURL     string
}

// QRCodeLoginStatusResult holds the current state returned by the QR-code
// login status endpoint.
type QRCodeLoginStatusResult struct {
	LoginStatus   int
	Token         string
	QRCodeJumpURL string
	Raw           map[string]any
}

// GenerateQRCodeLogin requests a fresh QR-code login URL and returns the
// bootstrap credentials used by the status and exchange endpoints.
func (c *Client) GenerateQRCodeLogin() (*QRCodeLoginInfo, error) {
	return c.GenerateQRCodeLoginContext(context.Background())
}

// GenerateQRCodeLoginContext requests a fresh QR-code login URL using ctx.
func (c *Client) GenerateQRCodeLoginContext(ctx context.Context) (*QRCodeLoginInfo, error) {
	return c.generateQRCodeLoginContext(ctx)
}

// GenerateQRCodeLoginWithGuest requests a QR-code login URL using a guest
// session. The official logged-out client uses this path before polling the
// login status.
func (c *Client) GenerateQRCodeLoginWithGuest(session *GuestSession) (*QRCodeLoginInfo, error) {
	return c.GenerateQRCodeLoginWithGuestContext(context.Background(), session)
}

// GenerateQRCodeLoginWithGuestContext requests a QR-code login URL using ctx.
func (c *Client) GenerateQRCodeLoginWithGuestContext(ctx context.Context, session *GuestSession) (*QRCodeLoginInfo, error) {
	if session == nil || session.Token == "" || session.GuestID == "" {
		return nil, fmt.Errorf("guest session is incomplete")
	}
	return c.guestClient(session).generateQRCodeLoginContext(ctx)
}

func (c *Client) generateQRCodeLoginContext(ctx context.Context) (*QRCodeLoginInfo, error) {
	resp, err := c.DoContext(ctx, "POST", "/api/v1/qrcode/gen/login", map[string]any{})
	if err != nil {
		return nil, fmt.Errorf("generate QR code login: %w", err)
	}
	data, err := responseData(resp, "generate QR code login")
	if err != nil {
		return nil, err
	}

	info := &QRCodeLoginInfo{}
	info.Token, _ = data["token"].(string)
	info.StatusQueryTicket, _ = data["status_query_ticket"].(string)
	info.QRCodeJumpURL, _ = data["qrcode_jump_url"].(string)
	if info.Token == "" || info.StatusQueryTicket == "" || info.QRCodeJumpURL == "" {
		return nil, fmt.Errorf("generate QR code login response is incomplete")
	}
	return info, nil
}

// QRCodeLoginStatus polls the official QR-code login status endpoint using the
// bootstrap credentials returned by GenerateQRCodeLogin.
func (c *Client) QRCodeLoginStatus(info *QRCodeLoginInfo) (*QRCodeLoginStatusResult, error) {
	return c.QRCodeLoginStatusContext(context.Background(), info)
}

// QRCodeLoginStatusContext polls QR-code login status using ctx.
func (c *Client) QRCodeLoginStatusContext(ctx context.Context, info *QRCodeLoginInfo) (*QRCodeLoginStatusResult, error) {
	return c.qrCodeLoginStatusContext(ctx, info)
}

// QRCodeLoginStatusWithGuest polls the QR-code login status using the guest
// session that created the QR code.
func (c *Client) QRCodeLoginStatusWithGuest(session *GuestSession, info *QRCodeLoginInfo) (*QRCodeLoginStatusResult, error) {
	return c.QRCodeLoginStatusWithGuestContext(context.Background(), session, info)
}

// QRCodeLoginStatusWithGuestContext polls QR-code login status using ctx.
func (c *Client) QRCodeLoginStatusWithGuestContext(ctx context.Context, session *GuestSession, info *QRCodeLoginInfo) (*QRCodeLoginStatusResult, error) {
	if session == nil || session.Token == "" || session.GuestID == "" {
		return nil, fmt.Errorf("guest session is incomplete")
	}
	return c.guestClient(session).qrCodeLoginStatusContext(ctx, info)
}

func (c *Client) qrCodeLoginStatusContext(ctx context.Context, info *QRCodeLoginInfo) (*QRCodeLoginStatusResult, error) {
	if info == nil || info.Token == "" || info.QRCodeJumpURL == "" {
		return nil, fmt.Errorf("QR code login bootstrap credentials are incomplete")
	}

	body := map[string]any{
		"login_status":    1,
		"qrcode_jump_url": info.QRCodeJumpURL,
		"token":           info.Token,
	}
	resp, err := c.DoContext(ctx, "POST", "/api/v1/qrcode/login/status", body)
	if err != nil {
		return nil, fmt.Errorf("query QR code login status: %w", err)
	}
	data, err := responseData(resp, "QR code login status")
	if err != nil {
		return nil, err
	}

	result := &QRCodeLoginStatusResult{Raw: data}
	if status, ok := data["login_status"].(float64); ok {
		result.LoginStatus = int(status)
	}
	result.Token, _ = data["token"].(string)
	result.QRCodeJumpURL, _ = data["qrcode_jump_url"].(string)
	return result, nil
}

// LoginByQRCodeWithGuest exchanges a confirmed QR-code login for a user JWT.
func (c *Client) LoginByQRCodeWithGuest(session *GuestSession, info *QRCodeLoginInfo) (*LoginResult, error) {
	return c.LoginByQRCodeWithGuestContext(context.Background(), session, info)
}

// LoginByQRCodeWithGuestContext exchanges a confirmed QR-code login using ctx.
func (c *Client) LoginByQRCodeWithGuestContext(ctx context.Context, session *GuestSession, info *QRCodeLoginInfo) (*LoginResult, error) {
	if session == nil || session.Token == "" || session.GuestID == "" {
		return nil, fmt.Errorf("guest session is incomplete")
	}
	if info == nil || info.StatusQueryTicket == "" {
		return nil, fmt.Errorf("QR code login bootstrap credentials are incomplete")
	}

	body := map[string]any{
		"qrcode_jump_url": info.QRCodeJumpURL,
		"token":           info.Token,
	}
	resp, err := c.guestClient(session).DoContext(ctx, "POST", "/api/v1/login/by_qrcode", body)
	if err != nil {
		return nil, fmt.Errorf("login by QR code: %w", err)
	}
	data, err := responseData(resp, "QR code login")
	if err != nil {
		return nil, err
	}
	token, _ := data["token"].(string)
	if token == "" {
		return nil, fmt.Errorf("QR code login response has no token")
	}
	return &LoginResult{Token: token}, nil
}
