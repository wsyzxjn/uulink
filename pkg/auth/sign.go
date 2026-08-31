// Package auth implements UU Remote REST API authentication.
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"runtime"
	"sort"
	"strings"
)

const signKey = "alWiSzXZTLu3WfFnw13uBru3"

// Sign computes X-Param-SIGN for a UU Remote API request.
//
// Algorithm: HMAC-SHA256(key, material) where
//
//	material = METHOD + PATH(?query) + sorted(x-param-k=v joined by &) + body
func Sign(method string, rawURL string, headers map[string]string, body string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		u = &url.URL{Path: rawURL}
	}

	var b strings.Builder
	b.WriteString(strings.ToUpper(method))
	b.WriteString(u.Path)
	if u.RawQuery != "" {
		b.WriteByte('?')
		b.WriteString(u.RawQuery)
	}

	// Collect x-param-* headers (excluding x-param-sign), lowercase keys, sort
	var params []struct{ k, v string }
	for k, v := range headers {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-param-") && lk != "x-param-sign" {
			params = append(params, struct{ k, v string }{lk, v})
		}
	}
	sort.Slice(params, func(i, j int) bool { return params[i].k < params[j].k })

	for i, p := range params {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(p.k)
		b.WriteByte('=')
		b.WriteString(p.v)
	}

	if body != "" {
		b.WriteString(body)
	}

	mac := hmac.New(sha256.New, []byte(signKey))
	mac.Write([]byte(b.String()))
	return hex.EncodeToString(mac.Sum(nil))
}

func platformParams(goos string) (platform, versionName, versionCode string) {
	if goos == "windows" {
		return "1", "4.38.3", "9325"
	}
	return "4", "4.38.0", "616"
}

// BuildHeaders returns the full set of authentication headers for an API request.
func BuildHeaders(cfg *Config, ts string) map[string]string {
	platform, versionName, versionCode := platformParams(runtime.GOOS)
	headers := map[string]string{
		"X-Param-PLAT":      platform,
		"X-Param-VN":        versionName,
		"X-Param-VC":        versionCode,
		"X-Param-PKGN":      "com.netease.uuremote",
		"X-Param-CHN":       "gwqd",
		"X-Param-LANG":      "zh-CN",
		"X-Param-CNT":       "CN",
		"X-Param-REL":       "prod",
		"X-Param-OPR":       "None",
		"X-Param-TS":        ts,
		"X-Param-client-id": cfg.ClientID,
		"X-Param-device-id": cfg.DeviceID,
		"X-Param-user-id":   cfg.UserID,
	}
	if cfg.JWT != "" {
		headers["Authorization"] = fmt.Sprintf("Bearer %s", cfg.JWT)
	}
	if cfg.GuestID != "" {
		headers["X-Param-guest-id"] = cfg.GuestID
	}
	return headers
}

// Config holds credentials and identifiers for UU Remote API auth.
type Config struct {
	JWT      string        `json:"jwt"`
	ClientID string        `json:"client_id"` // IOPlatformUUID
	DeviceID string        `json:"device_id"` // this device id
	UserID   string        `json:"user_id"`
	GuestID  string        `json:"guest_id,omitempty"`
	Mappings []PortMapping `json:"mappings,omitempty"`
}

// PortMapping declares one UULink listener and its peer-side target.
type PortMapping struct {
	RuleID     string `json:"rule_id,omitempty"`
	LocalHost  string `json:"local_host,omitempty"`
	LocalPort  int    `json:"local_port"`
	RemoteHost string `json:"remote_host,omitempty"`
	RemotePort int    `json:"remote_port"`
}

// LoadConfigFile reads a JSON config file.
func LoadConfigFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &cfg, nil
}
