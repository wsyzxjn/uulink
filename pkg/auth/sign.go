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

func platformParams(goos string, cfgPlatform int) (platform, versionName, versionCode string) {
	if cfgPlatform == 1 || goos == "windows" {
		return "1", "4.38.3", "9325"
	}
	return "4", "4.38.0", "616"
}

// BuildHeaders returns the full set of authentication headers for an API request.
func BuildHeaders(cfg *Config, ts string) map[string]string {
	platform, versionName, versionCode := platformParams(runtime.GOOS, cfg.Platform)
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
	JWT          string        `json:"jwt"`
	ClientID     string        `json:"client_id"` // IOPlatformUUID
	DeviceID     string        `json:"device_id"` // this device id
	UserID       string        `json:"user_id"`
	Hostname     string        `json:"hostname,omitempty"`
	GuestID      string        `json:"guest_id,omitempty"`
	Platform     int           `json:"platform,omitempty"`
	Mappings     []PortMapping `json:"mappings,omitempty"`
	AllowLAN     bool          `json:"allow_lan,omitempty"`
	AllowedPorts []int         `json:"allowed_ports,omitempty"`
	Sessions     int           `json:"sessions,omitempty"`
}

// PortMapping declares one UULink listener and its peer-side target.
// Supports both single ports (int) and ranges (string, e.g. "9000-9010").
type PortMapping struct {
	RuleID      string `json:"rule_id,omitempty"`
	LocalHost   string `json:"local_host,omitempty"`
	LocalPort   int    `json:"local_port,omitempty"`
	LocalRange  string `json:"local_range,omitempty"`
	RemoteHost  string `json:"remote_host,omitempty"`
	RemotePort  int    `json:"remote_port,omitempty"`
	RemoteRange string `json:"remote_range,omitempty"`
	Range       string `json:"range,omitempty"`
}

// UnmarshalJSON supports local_port and remote_port as either int or string range.
func (m *PortMapping) UnmarshalJSON(data []byte) error {
	var raw struct {
		RuleID      string `json:"rule_id"`
		LocalHost   string `json:"local_host"`
		LocalPort   any    `json:"local_port"`
		LocalRange  string `json:"local_range"`
		RemoteHost  string `json:"remote_host"`
		RemotePort  any    `json:"remote_port"`
		RemoteRange string `json:"remote_range"`
		Range       string `json:"range"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	m.RuleID = raw.RuleID
	m.LocalHost = raw.LocalHost
	m.RemoteHost = raw.RemoteHost
	m.LocalRange = raw.LocalRange
	m.RemoteRange = raw.RemoteRange
	m.Range = raw.Range

	if raw.LocalPort != nil {
		switch v := raw.LocalPort.(type) {
		case float64:
			m.LocalPort = int(v)
		case string:
			m.LocalRange = v
		}
	}
	if raw.RemotePort != nil {
		switch v := raw.RemotePort.(type) {
		case float64:
			m.RemotePort = int(v)
		case string:
			m.RemoteRange = v
		}
	}
	return nil
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
