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

// UserAgent returns the official User-Agent matching the platform.
func UserAgent(goos string, cfgPlatform int) string {
	if cfgPlatform == 1 || goos == "windows" {
		return "UURemote/4.38.3 (com.netease.uuremote; build:9325; Windows 10)"
	}
	return "UURemote/4.38.0 (com.netease.uuremote; build:616; macOS 27.0.0) Alamofire/5.7.1"
}

// BuildHeaders returns the full set of authentication headers for an API request.
func BuildHeaders(cfg *Config, ts string) map[string]string {
	cfgPlatform := 0
	if cfg != nil {
		cfgPlatform = cfg.Platform
	}
	platform, versionName, versionCode := platformParams(runtime.GOOS, cfgPlatform)
	if cfg != nil {
		if cfg.VersionName != "" {
			versionName = cfg.VersionName
		}
		if cfg.VersionCode != "" {
			versionCode = cfg.VersionCode
		}
	}
	if envVN := os.Getenv("UULINK_CLIENT_VN"); envVN != "" {
		versionName = envVN
	}
	if envVC := os.Getenv("UULINK_CLIENT_VC"); envVC != "" {
		versionCode = envVC
	}
	headers := map[string]string{
		"User-Agent":        UserAgent(runtime.GOOS, cfgPlatform),
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
	JWT             string        `json:"jwt"`
	ClientID        string        `json:"client_id"` // IOPlatformUUID
	DeviceID        string        `json:"device_id"` // this device id
	UserID          string        `json:"user_id"`
	Hostname        string        `json:"hostname,omitempty"`
	GuestID         string        `json:"guest_id,omitempty"`
	Platform        int           `json:"platform,omitempty"`
	Mappings        []PortMapping `json:"mappings,omitempty"`
	AllowLAN        bool          `json:"allow_lan,omitempty"`
	AllowedPorts    []int         `json:"allowed_ports,omitempty"`
	SessionMode     string        `json:"session_mode,omitempty"`
	Sessions        int           `json:"sessions,omitempty"`
	VersionName     string        `json:"version_name,omitempty"`
	VersionCode     string        `json:"version_code,omitempty"`
	StreamerVersion string        `json:"streamer_version,omitempty"`
	// Custom-code assistance: a fixed verification code plus the share this
	// config connects to or serves, so a client can start without flags.
	CustomCode string `json:"custom_code,omitempty"`
	ShareID    string `json:"share_id,omitempty"`
	ShareCode  string `json:"share_code,omitempty"`
	// Identity of the accountless device registered by the unbound guest
	// server, reused across restarts so the assistance ID stays stable.
	UnboundClientID string `json:"unbound_client_id,omitempty"`
	UnboundDeviceID string `json:"unbound_device_id,omitempty"`

	// extra keeps the keys this version does not know about, so rewriting
	// the file after a login does not silently drop a user's own entries
	// or fields added by a newer release.
	extra map[string]json.RawMessage
}

// configAlias has the same fields as Config without its methods, so the
// custom (un)marshalers can delegate to the default encoding.
type configAlias Config

// UnmarshalJSON decodes the known fields and retains every other key.
func (c *Config) UnmarshalJSON(data []byte) error {
	var known configAlias
	if err := json.Unmarshal(data, &known); err != nil {
		return err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*c = Config(known)
	for _, key := range knownConfigKeys() {
		delete(raw, key)
	}
	if len(raw) > 0 {
		c.extra = raw
	}
	return nil
}

// MarshalJSON encodes the known fields followed by the retained extra keys.
func (c Config) MarshalJSON() ([]byte, error) {
	data, err := json.Marshal(configAlias(c))
	if err != nil {
		return nil, err
	}
	if len(c.extra) == 0 {
		return data, nil
	}
	var merged map[string]json.RawMessage
	if err := json.Unmarshal(data, &merged); err != nil {
		return nil, err
	}
	for key, value := range c.extra {
		if _, known := merged[key]; !known {
			merged[key] = value
		}
	}
	return json.Marshal(merged)
}

// knownConfigKeys lists the JSON keys that Config decodes itself.
func knownConfigKeys() []string {
	data, _ := json.Marshal(configAlias{})
	var probe map[string]json.RawMessage
	_ = json.Unmarshal(data, &probe)
	keys := make([]string, 0, len(probe)+16)
	for key := range probe {
		keys = append(keys, key)
	}
	// omitempty fields are absent from the probe; list them explicitly.
	return append(keys,
		"hostname", "guest_id", "platform", "mappings", "allow_lan", "allowed_ports",
		"session_mode", "sessions", "version_name", "version_code", "streamer_version",
		"custom_code", "share_id", "share_code", "unbound_client_id", "unbound_device_id",
	)
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

// MarshalJSON writes a range back in the form it was read: a string
// local_port/remote_port, so a rewritten config still looks like the user's.
func (m PortMapping) MarshalJSON() ([]byte, error) {
	out := map[string]any{}
	if m.RuleID != "" {
		out["rule_id"] = m.RuleID
	}
	if m.LocalHost != "" {
		out["local_host"] = m.LocalHost
	}
	if m.RemoteHost != "" {
		out["remote_host"] = m.RemoteHost
	}
	switch {
	case m.LocalRange != "":
		out["local_port"] = m.LocalRange
	case m.LocalPort != 0:
		out["local_port"] = m.LocalPort
	}
	switch {
	case m.RemoteRange != "":
		out["remote_port"] = m.RemoteRange
	case m.RemotePort != 0:
		out["remote_port"] = m.RemotePort
	}
	if m.Range != "" {
		out["range"] = m.Range
	}
	return json.Marshal(out)
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
