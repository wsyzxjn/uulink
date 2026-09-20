package remoteconfig

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/wsyzxjn/uulink/pkg/auth"
	"github.com/wsyzxjn/uulink/pkg/tunnel"
)

// RemoteShareConfig holds the share information and mapping rules fetched from
// a remote configuration URL.
type RemoteShareConfig struct {
	ShareID     string             `json:"share_id,omitempty"`
	ConnectID   string             `json:"connect_id,omitempty"`
	DeviceID    string             `json:"device_id,omitempty"`
	ShareCode   string             `json:"share_code,omitempty"`
	ConnectCode string             `json:"connect_code,omitempty"`
	CustomCode  string             `json:"custom_code,omitempty"`
	Mappings    []auth.PortMapping `json:"mappings,omitempty"`
	Mapping     string             `json:"mapping,omitempty"`
	LocalPort   int                `json:"local_port,omitempty"`
	RemotePort  int                `json:"remote_port,omitempty"`
	Transport   string             `json:"transport,omitempty"` // "auto" or "relay"
	LANMOTD     string             `json:"lan_motd,omitempty"`
	LANPort     int                `json:"lan_port,omitempty"`
	UpdatedAt   string             `json:"updated_at,omitempty"`
}

// EffectiveShareID returns ShareID, ConnectID, or DeviceID.
func (c *RemoteShareConfig) EffectiveShareID() string {
	if c.ShareID != "" {
		return c.ShareID
	}
	if c.ConnectID != "" {
		return c.ConnectID
	}
	return c.DeviceID
}

// EffectiveShareCode returns CustomCode, ShareCode, or ConnectCode.
func (c *RemoteShareConfig) EffectiveShareCode() string {
	if c.CustomCode != "" {
		return c.CustomCode
	}
	if c.ShareCode != "" {
		return c.ShareCode
	}
	return c.ConnectCode
}

// Validate checks that the share configuration contains the required identifiers.
func (c *RemoteShareConfig) Validate() error {
	if c.EffectiveShareID() == "" {
		return fmt.Errorf("remote config missing share_id / connect_id")
	}
	if c.EffectiveShareCode() == "" {
		return fmt.Errorf("remote config missing share_code / connect_code")
	}
	return nil
}

// Fetch loads a RemoteShareConfig from rawURL over HTTP(S).
func Fetch(rawURL string, timeout time.Duration) (*RemoteShareConfig, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return FetchWithClient(&http.Client{Timeout: timeout}, rawURL)
}

// FetchWithClient loads a RemoteShareConfig using the specified HTTP client.
func FetchWithClient(client *http.Client, rawURL string) (*RemoteShareConfig, error) {
	if rawURL == "" {
		return nil, fmt.Errorf("remote config URL is empty")
	}

	var data []byte
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		filePath := strings.TrimPrefix(rawURL, "file://")
		var err error
		data, err = os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("read remote config file %s: %w", filePath, err)
		}
	} else {
		req, err := http.NewRequest("GET", rawURL, nil)
		if err != nil {
			return nil, fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("User-Agent", auth.UserAgent(runtime.GOOS, 0))
		req.Header.Set("Accept", "application/json, */*")

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("fetch remote config from %s: %w", rawURL, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			return nil, fmt.Errorf("fetch remote config from %s: HTTP %d: %s", rawURL, resp.StatusCode, strings.TrimSpace(string(body)))
		}

		var errRead error
		data, errRead = io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		if errRead != nil {
			return nil, fmt.Errorf("read remote config body: %w", errRead)
		}
	}

	var cfg RemoteShareConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("unmarshal remote config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Publish sends share config to a webhook or endpoint via HTTP POST.
func Publish(publishURL, secret string, cfg *RemoteShareConfig, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return PublishWithClient(&http.Client{Timeout: timeout}, publishURL, secret, cfg)
}

// PublishWithClient sends share config using the specified HTTP client.
func PublishWithClient(client *http.Client, publishURL, secret string, cfg *RemoteShareConfig) error {
	if publishURL == "" {
		return fmt.Errorf("publish URL is empty")
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal publish payload: %w", err)
	}

	req, err := http.NewRequest("POST", publishURL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("build publish request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", auth.UserAgent(runtime.GOOS, 0))
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("post publish to %s: %w", publishURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("publish to %s failed: HTTP %d: %s", publishURL, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// Rules converts remote mappings and optional CLI overrides into tunnel.Rule items.
func (c *RemoteShareConfig) Rules(ruleIDFlag, mappingFlag, localHost, cliLocalPort, remoteHost, cliRemotePort string) ([]tunnel.Rule, error) {
	mappings := append([]auth.PortMapping(nil), c.Mappings...)
	if c.LocalPort > 0 && c.RemotePort > 0 {
		mappings = append(mappings, auth.PortMapping{
			LocalPort:  c.LocalPort,
			RemotePort: c.RemotePort,
		})
	}
	if c.Mapping != "" && mappingFlag == "" {
		mappingFlag = c.Mapping
	}
	return tunnel.BuildRules(mappings, tunnel.CLIMapping{
		RuleID:     ruleIDFlag,
		Mapping:    mappingFlag,
		LocalHost:  localHost,
		LocalPort:  cliLocalPort,
		RemoteHost: remoteHost,
		RemotePort: cliRemotePort,
	})
}
