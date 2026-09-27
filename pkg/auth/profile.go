package auth

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// Compatibility defaults are from the working macOS 4.38.0 / Windows 4.38.3
// clients. They are protocol identities, not claims about the host hardware.
const (
	DefaultAPIBaseURL         = "https://api.nrd.nie.163.com"
	DefaultStreamerVersion    = "V4.5.3"
	DefaultWebSocketUserAgent = "WebSocket++/0.8.2"
	defaultSigningKey         = "alWiSzXZTLu3WfFnw13uBru3"
	WindowsPlatform           = 1
	MacPlatform               = 4
)

// ClientProfile overrides the upstream client identity without changing login IDs.
type ClientProfile struct {
	WebSocketUserAgent string `json:"websocket_user_agent,omitempty"`
	PackageName        string `json:"package_name,omitempty"`
	Channel            string `json:"channel,omitempty"`
	Language           string `json:"language,omitempty"`
	Country            string `json:"country,omitempty"`
	Release            string `json:"release,omitempty"`
	Operator           string `json:"operator,omitempty"`
	SigningKey         string `json:"signing_key,omitempty"`
	UserAgentOS        string `json:"user_agent_os,omitempty"`
	UserAgentSuffix    string `json:"user_agent_suffix,omitempty"`
}

// Identity is resolved once per use, with environment overrides taking precedence
// over the config for both REST headers and WebRTC/signaling handshakes.
type Identity struct {
	ClientProfile
	Platform                                  int
	VersionName, VersionCode, StreamerVersion string
}

func (c *Config) Identity() Identity { return c.identityFor(runtime.GOOS) }

func (c *Config) identityFor(goos string) Identity {
	if c == nil {
		c = &Config{}
	}
	p := c.Platform
	if p == 0 {
		p = MacPlatform
		if goos == "windows" {
			p = WindowsPlatform
		}
	}
	i := Identity{Platform: p, ClientProfile: c.ClientProfile, VersionName: c.VersionName, VersionCode: c.VersionCode, StreamerVersion: c.StreamerVersion}
	vn, vc, uaOS, suffix := "4.38.0", "616", "macOS 27.0.0", " Alamofire/5.7.1"
	if p == WindowsPlatform {
		vn, vc, uaOS, suffix = "4.38.3", "9325", "Windows 10", ""
	}
	for _, value := range []struct {
		dst      *string
		fallback string
	}{
		{&i.WebSocketUserAgent, DefaultWebSocketUserAgent}, {&i.VersionName, vn}, {&i.VersionCode, vc}, {&i.StreamerVersion, DefaultStreamerVersion},
		{&i.PackageName, "com.netease.uuremote"}, {&i.Channel, "gwqd"},
		{&i.Language, "zh-CN"}, {&i.Country, "CN"}, {&i.Release, "prod"},
		{&i.Operator, "None"}, {&i.SigningKey, defaultSigningKey},
		{&i.UserAgentOS, uaOS}, {&i.UserAgentSuffix, suffix},
	} {
		if *value.dst == "" {
			*value.dst = value.fallback
		}
	}
	if v := os.Getenv("UULINK_CLIENT_VN"); v != "" {
		i.VersionName = v
	}
	if v := os.Getenv("UULINK_CLIENT_VC"); v != "" {
		i.VersionCode = v
	}
	if v := os.Getenv("UULINK_STREAMER_VERSION"); v != "" {
		i.StreamerVersion = v
	}
	return i
}

func (i Identity) UserAgent() string {
	return fmt.Sprintf("UURemote/%s (%s; build:%s; %s)%s", i.VersionName, i.PackageName, i.VersionCode, i.UserAgentOS, i.UserAgentSuffix)
}

func (i Identity) Validate() error {
	if i.Platform != WindowsPlatform && i.Platform != MacPlatform {
		return fmt.Errorf("platform must be 1 (Windows) or 4 (macOS)")
	}
	if code, err := strconv.ParseUint(i.VersionCode, 10, 32); err != nil || code == 0 {
		return fmt.Errorf("version_code must be a positive integer")
	}
	for _, s := range []string{i.VersionName, i.VersionCode, i.StreamerVersion, i.PackageName, i.Channel, i.Language, i.Country, i.Release, i.Operator, i.UserAgentOS, i.UserAgentSuffix, i.WebSocketUserAgent} {
		if strings.ContainsAny(s, "\r\n\x00") {
			return fmt.Errorf("client identity values must not contain header control characters")
		}
	}
	return nil
}

// DeviceProfile describes optional registration metadata. Device/client IDs,
// names, MAC derivation and controllability remain owned by the registration flow.
type DeviceProfile struct {
	OS              string   `json:"os,omitempty"`
	Memory          string   `json:"memory,omitempty"`
	CPU             string   `json:"cpu,omitempty"`
	Video           []string `json:"video,omitempty"`
	Resolution      string   `json:"resolution,omitempty"`
	Screen          string   `json:"screen,omitempty"`
	SystemName      string   `json:"system_name,omitempty"`
	SystemVersion   string   `json:"system_version,omitempty"`
	Model           string   `json:"model,omitempty"`
	ModelIdentifier string   `json:"model_identifier,omitempty"`
	ModelNumber     string   `json:"model_number,omitempty"`
	BaseBoard       string   `json:"base_board,omitempty"`
	DPI             int      `json:"dpi,omitempty"`
}

type DeviceProfiles struct {
	Mac     DeviceProfile `json:"mac,omitempty"`
	Windows DeviceProfile `json:"windows,omitempty"`
}

// RegistrationMetadata retains proven upstream-compatible templates by default;
// it does not collect physical machine details or expose unique hardware IDs.
func (d DeviceProfiles) RegistrationMetadata(platform int) map[string]any {
	body := map[string]any{
		"os": "版本27.0（版号26A5421a）", "resolution": "2560x1440", "system_name": "macOS",
		"memory": "16384", "model_number": "MU9D3CH/A", "model": "Mac", "cpu": "Apple M4",
		"video": []string{"Apple M4"}, "model_identifier": "Mac16,10", "system_version": "27.0.0", "dpi": 144,
	}
	p := d.Mac
	if platform == WindowsPlatform {
		p = d.Windows
		body = map[string]any{"os": "Microsoft Windows NT 10.0.26200.0", "base_board": "Virtual", "cpu": "Virtual CPU", "video": []string{"Virtual GPU"}, "memory": "16384", "screen": "1920x1080", "platform": WindowsPlatform}
	}
	for key, value := range map[string]string{
		"os": p.OS, "memory": p.Memory, "cpu": p.CPU, "resolution": p.Resolution, "screen": p.Screen,
		"system_name": p.SystemName, "system_version": p.SystemVersion, "model": p.Model,
		"model_identifier": p.ModelIdentifier, "model_number": p.ModelNumber, "base_board": p.BaseBoard,
	} {
		if value != "" {
			body[key] = value
		}
	}
	if p.Video != nil {
		body["video"] = append([]string{}, p.Video...)
	}
	if p.DPI != 0 {
		body["dpi"] = p.DPI
	}
	return body
}
