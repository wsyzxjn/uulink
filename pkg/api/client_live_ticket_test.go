package api

import (
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wsyzxjn/uulink/pkg/auth"
)

func TestLiveWebLoginTicket(t *testing.T) {
	if os.Getenv("UULINK_LIVE") == "" {
		t.Skip("set UULINK_LIVE=1 to run live tests")
	}

	cfg, err := auth.LoadConfigFile("../../config.json")
	if err != nil {
		t.Skipf("config.json not available: %v", err)
	}

	resp, err := NewClient(cfg).Do("GET", "/api/v1/user/ticket/for/wvlogin", nil)
	if err != nil {
		t.Fatalf("get web login ticket: %v", err)
	}
	if code, ok := resp["code"].(float64); ok && code != 0 {
		t.Fatalf("get web login ticket failed, code %v: %v", code, resp["msg"])
	}

	data, ok := resp["data"].(map[string]any)
	if !ok {
		t.Fatalf("web login ticket response has no data: %v", resp)
	}
	for key, value := range data {
		if text, ok := value.(string); ok {
			t.Logf("%s: string length %d", key, len(text))
			continue
		}
		t.Logf("%s: %T", key, value)
	}
}

func TestLiveUserInfoResponseHeaders(t *testing.T) {
	if os.Getenv("UULINK_LIVE") == "" {
		t.Skip("set UULINK_LIVE=1 to run live tests")
	}

	cfg, err := auth.LoadConfigFile("../../config.json")
	if err != nil {
		t.Skipf("config.json not available: %v", err)
	}

	ts := strconv.FormatInt(time.Now().Unix(), 10)
	headers := auth.BuildHeaders(cfg, ts)
	sign := auth.Sign("GET", "https://api.nrd.nie.163.com/api/v1/user/info", headers, "")
	headers["X-Param-SIGN"] = sign

	req, err := http.NewRequest("GET", "https://api.nrd.nie.163.com/api/v1/user/info", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("http do: %v", err)
	}
	defer resp.Body.Close()

	for key, values := range resp.Header {
		lower := strings.ToLower(key)
		if strings.Contains(lower, "token") || strings.Contains(lower, "authorization") ||
			strings.Contains(lower, "refresh") || strings.Contains(lower, "renew") {
			total := 0
			for _, value := range values {
				total += len(value)
			}
			t.Logf("%s: %d values, total length %d", key, len(values), total)
		}
	}
}
