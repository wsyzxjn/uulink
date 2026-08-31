package api

import (
	"os"
	"testing"

	"github.com/user/uulink/pkg/auth"
)

func TestLiveQRCodeLoginProbe(t *testing.T) {
	if os.Getenv("UULINK_QR_PROBE") != "1" {
		t.Skip("set UULINK_QR_PROBE=1 to probe the live QR login endpoints")
	}

	cfg, err := auth.LoadConfigFile("../../config.json")
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	cfg.JWT = ""
	cfg.UserID = ""

	client := NewClient(cfg)
	guest, err := client.CreateGuest()
	if err != nil {
		t.Fatalf("create guest: %v", err)
	}
	qrCode, err := client.GenerateQRCodeLoginWithGuest(guest)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	t.Logf("gen: token_len=%d status_query_ticket_len=%d qrcode_jump_url_len=%d",
		len(qrCode.Token), len(qrCode.StatusQueryTicket), len(qrCode.QRCodeJumpURL))
	token := qrCode.Token
	statusTicket := qrCode.StatusQueryTicket
	qrcodeJumpURL := qrCode.QRCodeJumpURL
	if token == "" || statusTicket == "" || qrcodeJumpURL == "" {
		t.Fatalf("QR code login response is incomplete")
	}

	status, err := client.QRCodeLoginStatusWithGuest(guest, qrCode)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	t.Logf("status: login_status=%d token_len=%d qrcode_jump_url_len=%d keys=%v",
		status.LoginStatus, len(status.Token), len(status.QRCodeJumpURL), mapKeys(status.Raw))
}

func mapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	return keys
}
