package remoteconfig

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/user/uulink/pkg/auth"
	"github.com/user/uulink/pkg/tunnel"
)

// RemoteShareConfig holds the share information and mapping rules fetched from
// a remote configuration URL.
type RemoteShareConfig struct {
	ShareID     string             `json:"share_id"`
	ConnectID   string             `json:"connect_id,omitempty"`
	ShareCode   string             `json:"share_code"`
	ConnectCode string             `json:"connect_code,omitempty"`
	Mappings    []auth.PortMapping `json:"mappings,omitempty"`
	Mapping     string             `json:"mapping,omitempty"`
	LocalPort   int                `json:"local_port,omitempty"`
	RemotePort  int                `json:"remote_port,omitempty"`
	ForceRelay  bool               `json:"force_relay,omitempty"`
	LANMOTD     string             `json:"lan_motd,omitempty"`
	LANPort     int                `json:"lan_port,omitempty"`
	UpdatedAt   string             `json:"updated_at,omitempty"`
}

// EffectiveShareID returns ShareID or ConnectID.
func (c *RemoteShareConfig) EffectiveShareID() string {
	if c.ShareID != "" {
		return c.ShareID
	}
	return c.ConnectID
}

// EffectiveShareCode returns ShareCode or ConnectCode.
func (c *RemoteShareConfig) EffectiveShareCode() string {
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
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", "uulink")
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

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil, fmt.Errorf("read remote config body: %w", err)
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
	req.Header.Set("User-Agent", "uulink")
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
	var mappings []auth.PortMapping
	mappings = append(mappings, c.Mappings...)
	if c.LocalPort > 0 && c.RemotePort > 0 {
		mappings = append(mappings, auth.PortMapping{
			LocalPort:  c.LocalPort,
			RemotePort: c.RemotePort,
		})
	}
	if c.Mapping != "" && mappingFlag == "" {
		mappingFlag = c.Mapping
	}

	var rules []tunnel.Rule
	seen := make(map[string]bool)

	appendRule := func(rule tunnel.Rule) error {
		if rule.ID == "" {
			rule.ID = tunnel.GenerateRuleID()
		}
		if _, err := strconv.ParseUint(rule.ID, 10, 64); err != nil {
			return fmt.Errorf("rule %s: rule-id must be numeric: %w", rule.ID, err)
		}
		if rule.LocalPort <= 0 || rule.TargetPort <= 0 {
			return fmt.Errorf("rule %s: local_port and remote_port must be positive", rule.ID)
		}
		if seen[rule.ID] {
			return fmt.Errorf("duplicate rule ID %s", rule.ID)
		}
		seen[rule.ID] = true
		rules = append(rules, rule)
		return nil
	}

	for _, mapping := range mappings {
		lHost := mapping.LocalHost
		if lHost == "" {
			lHost = "127.0.0.1"
		}
		rHost := mapping.RemoteHost
		if rHost == "" {
			rHost = "127.0.0.1"
		}

		var pairs []tunnel.PortPair
		var err error
		switch {
		case mapping.Range != "":
			pairs, err = tunnel.ParsePortMappingSpec(mapping.Range)
		case mapping.LocalRange != "" || mapping.RemoteRange != "":
			lSpec := mapping.LocalRange
			if lSpec == "" && mapping.LocalPort != 0 {
				lSpec = strconv.Itoa(mapping.LocalPort)
			}
			rSpec := mapping.RemoteRange
			if rSpec == "" && mapping.RemotePort != 0 {
				rSpec = strconv.Itoa(mapping.RemotePort)
			}
			pairs, err = tunnel.ExpandPortRange(lSpec, rSpec)
		case mapping.LocalPort != 0 && mapping.RemotePort != 0:
			pairs = []tunnel.PortPair{{LocalPort: mapping.LocalPort, RemotePort: mapping.RemotePort}}
		default:
			return nil, fmt.Errorf("mapping must specify local and remote ports or ranges")
		}
		if err != nil {
			return nil, fmt.Errorf("remote mapping rule: %w", err)
		}

		for _, pair := range pairs {
			rID := mapping.RuleID
			if len(pairs) > 1 {
				rID = ""
			}
			if err := appendRule(tunnel.Rule{
				ID:         rID,
				LocalHost:  lHost,
				LocalPort:  pair.LocalPort,
				TargetHost: rHost,
				TargetPort: pair.RemotePort,
			}); err != nil {
				return nil, err
			}
		}
	}

	if mappingFlag != "" {
		pairs, err := tunnel.ParsePortMappingSpec(mappingFlag)
		if err != nil {
			return nil, fmt.Errorf("mapping flag: %w", err)
		}
		for _, pair := range pairs {
			rID := ruleIDFlag
			if len(pairs) > 1 {
				rID = ""
			}
			if err := appendRule(tunnel.Rule{
				ID:         rID,
				LocalHost:  localHost,
				LocalPort:  pair.LocalPort,
				TargetHost: remoteHost,
				TargetPort: pair.RemotePort,
			}); err != nil {
				return nil, err
			}
		}
	}
	if cliLocalPort != "" || cliRemotePort != "" {
		if cliLocalPort == "" || cliRemotePort == "" {
			return nil, fmt.Errorf("both -local and -remote-port are required for CLI mapping")
		}
		pairs, err := tunnel.ExpandPortRange(cliLocalPort, cliRemotePort)
		if err != nil {
			return nil, fmt.Errorf("cli port mapping: %w", err)
		}
		for _, pair := range pairs {
			rID := ruleIDFlag
			if len(pairs) > 1 {
				rID = ""
			}
			if err := appendRule(tunnel.Rule{
				ID:         rID,
				LocalHost:  localHost,
				LocalPort:  pair.LocalPort,
				TargetHost: remoteHost,
				TargetPort: pair.RemotePort,
			}); err != nil {
				return nil, err
			}
		}
	}

	return rules, nil
}
