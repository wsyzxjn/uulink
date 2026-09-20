package main

import (
	crand "crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/wsyzxjn/uulink/pkg/auth"
	"github.com/wsyzxjn/uulink/pkg/logging"
	"github.com/wsyzxjn/uulink/pkg/peer"
	"github.com/wsyzxjn/uulink/pkg/tunnel"
)

// Shared flag groups. Every tunnel command binds the same mapping and security
// flags and every controller the same transport flags, so the surface stays
// consistent across subcommands.

// mappingFlags declare the local listeners of a tunnel command.
type mappingFlags struct {
	ruleID     string
	mapping    string
	localHost  string
	localPort  string
	remoteHost string
	remotePort string
}

func (m *mappingFlags) bind(fs *flag.FlagSet) {
	fs.StringVar(&m.localPort, "local", "", "local port or port range to listen on (e.g. 8080 or 9000-9010)")
	fs.StringVar(&m.localHost, "local-host", "127.0.0.1", "local address to listen on")
	fs.StringVar(&m.remotePort, "remote-port", "", "remote target port or port range (e.g. 8080 or 9000-9010)")
	fs.StringVar(&m.remoteHost, "remote-host", "127.0.0.1", "remote target host")
	fs.StringVar(&m.mapping, "mapping", "", "port forwarding rule or range (e.g. 8080:8080 or 9000-9010:8000-8010)")
	fs.StringVar(&m.ruleID, "rule-id", "", "registered rule ID on the remote device (must match)")
}

// rules expands the config mappings plus these flags into listener rules. A
// mistake here is a usage error.
func (m *mappingFlags) rules(cfg *auth.Config) ([]tunnel.Rule, error) {
	rules, err := configuredRules(cfg, m.ruleID, m.mapping, m.localHost, m.localPort, m.remoteHost, m.remotePort)
	if err != nil {
		return nil, usageErrorf("configure mappings: %w", err)
	}
	return rules, nil
}

// policyFlags restrict the targets that incoming CONNECT frames may dial.
type policyFlags struct {
	allowLAN     bool
	allowedPorts string
}

func (p *policyFlags) bind(fs *flag.FlagSet) {
	fs.BoolVar(&p.allowLAN, "allow-lan", false, "allow incoming mappings to target non-loopback LAN/WAN addresses (default: loopback only)")
	fs.StringVar(&p.allowedPorts, "allowed-ports", "", "comma-separated list or ranges of allowed target ports (e.g. 22,8080,9000-9010)")
}

func (p *policyFlags) policy(cfg *auth.Config) (tunnel.SecurityPolicy, error) {
	policy, err := buildSecurityPolicy(cfg, p.allowLAN, p.allowedPorts)
	if err != nil {
		return tunnel.SecurityPolicy{}, usageErrorf("configure security policy: %w", err)
	}
	return policy, nil
}

// sessionFlags select the relay pool size.
type sessionFlags struct {
	sessions string
}

func (s *sessionFlags) bind(fs *flag.FlagSet) {
	fs.StringVar(&s.sessions, "sessions", "", "relay session mode: auto, or a fixed count from 1 to 16 (default: auto)")
}

func (s *sessionFlags) resolve(cfg *auth.Config) (sessionPolicy, error) {
	policy, err := resolveSessionPolicy(s.sessions, cfg.SessionMode, cfg.Sessions)
	if err != nil {
		return sessionPolicy{}, usageErrorf("resolve session policy: %w", err)
	}
	logging.Infof("session policy: mode=%s target=%d", policy.mode, policy.target)
	return policy, nil
}

// controllerFlags are shared by every command that joins a room as the
// controlling side.
type controllerFlags struct {
	transport    string
	p2pTimeout   time.Duration
	lanDiscovery bool
	lanMotd      string
	// Debugging aids.
	capability      string
	controlDeviceID string
}

func (c *controllerFlags) bind(fs *flag.FlagSet) {
	fs.StringVar(&c.transport, "transport", "auto", "WebRTC transport policy: auto, or relay to require a TURN relay")
	fs.DurationVar(&c.p2pTimeout, "p2p-timeout", defaultP2PTimeout, "how long to wait for a direct P2P connection before retrying with a TURN relay (0 disables the fallback)")
	fs.BoolVar(&c.lanDiscovery, "lan-discovery", false, "announce the first forwarded port as a Minecraft LAN server")
	fs.StringVar(&c.lanMotd, "lan-motd", "", "MOTD text for the Minecraft LAN announcement")
	fs.StringVar(&c.capability, "cap", "", debugUsagePrefix+"override the ConnectOptions capability blob (hex, e.g. 08061002180120023002380240024801)")
	fs.StringVar(&c.controlDeviceID, "control-device-id", "", debugUsagePrefix+"device ID sent in the control ConnectOptions attachment (defaults to the config device_id)")
	bindExperimentFlags(fs)
}

func (c *controllerFlags) transportMode() (peer.TransportMode, error) {
	mode, err := peer.ParseTransportMode(c.transport)
	if err != nil {
		return "", usageErrorf("parse transport mode: %w", err)
	}
	if c.p2pTimeout < 0 {
		return "", usageErrorf("-p2p-timeout must be zero or positive")
	}
	return mode, nil
}

// loadConfig reads the config file. Commands that can run without an account
// (accountless servers, share joins, login itself) set init so a missing file
// is created with a fresh client identity instead of being an error.
func loadConfig(g *globalOptions, init bool) (*auth.Config, error) {
	var cfg *auth.Config
	var err error
	if init {
		cfg, err = auth.LoadOrInitConfigFile(g.configPath)
	} else {
		cfg, err = auth.LoadConfigFile(g.configPath)
	}
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	return cfg, nil
}

// pushQueue runs the API work triggered by bmsg_push events on one goroutine,
// in arrival order, off the signaling read loop: the pushes for one room are
// a short causal sequence (control mode query, then remote control), and the
// read loop has to stay free for ping/pong.
type pushQueue struct {
	jobs chan func()
}

// pushQueueDepth bounds pending pushes; a room only ever has a handful.
const pushQueueDepth = 16

func newPushQueue(done <-chan struct{}) *pushQueue {
	q := &pushQueue{jobs: make(chan func(), pushQueueDepth)}
	go func() {
		for {
			select {
			case <-done:
				return
			case job := <-q.jobs:
				job()
			}
		}
	}()
	return q
}

func (q *pushQueue) submit(job func()) {
	select {
	case q.jobs <- job:
	default:
		logging.Warnf("[signaling] push queue is full; dropping a bmsg_push")
	}
}

// configuredRules expands the config mappings plus the command-line mapping
// flags into listener rules.
func configuredRules(cfg *auth.Config, ruleIDFlag, mappingFlag, localHost, cliLocalPort, remoteHost, cliRemotePort string) ([]tunnel.Rule, error) {
	return tunnel.BuildRules(cfg.Mappings, tunnel.CLIMapping{
		RuleID:     ruleIDFlag,
		Mapping:    mappingFlag,
		LocalHost:  localHost,
		LocalPort:  cliLocalPort,
		RemoteHost: remoteHost,
		RemotePort: cliRemotePort,
	})
}

func logActiveMappings(prefix string, rules []tunnel.Rule) {
	for _, rule := range rules {
		logging.Infof("%s: %s:%d -> peer-target %s:%d (rule %s)",
			prefix, rule.LocalHost, rule.LocalPort, rule.TargetHost, rule.TargetPort, rule.ID)
	}
}

func generateAppControlID() (string, error) {
	var b [16]byte
	if _, err := crand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// peerSender adapts peer.Peer to tunnel.FrameSender, wrapping frames in
// the signaling pb channel events.
type peerSender struct {
	peer *peer.Peer
}

func (s *peerSender) SendFrame(msg []byte) error {
	// PM protobuf messages are sent directly on FILE_DATA_CHANNEL.
	return s.peer.SendSignalPB(msg)
}

func mapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func buildSecurityPolicy(cfg *auth.Config, allowLAN bool, allowedPortsFlag string) (tunnel.SecurityPolicy, error) {
	policy := tunnel.SecurityPolicy{
		AllowLAN: allowLAN || cfg.AllowLAN,
	}
	if allowedPortsFlag != "" {
		ports, err := tunnel.ParseAllowedPorts(allowedPortsFlag)
		if err != nil {
			return tunnel.SecurityPolicy{}, fmt.Errorf("parse -allowed-ports: %w", err)
		}
		policy.AllowedPorts = ports
	} else if cfg.AllowedPorts != nil {
		ports := make(map[int]bool, len(cfg.AllowedPorts))
		for _, p := range cfg.AllowedPorts {
			if p <= 0 || p > 65535 {
				return tunnel.SecurityPolicy{}, fmt.Errorf("config allowed_ports: invalid port %d", p)
			}
			ports[p] = true
		}
		policy.AllowedPorts = ports
	}
	return policy, nil
}

func logSecurityPolicy(policy tunnel.SecurityPolicy) {
	if policy.AllowLAN {
		logging.Warnf("security policy: LAN/WAN target access enabled (-allow-lan)")
	} else {
		logging.Infof("security policy: target restricted to trusted loopback services (localhost/127.0.0.1)")
	}
	if policy.AllowedPorts != nil {
		if len(policy.AllowedPorts) == 0 {
			logging.Warnf("security policy: allowed target ports whitelist is empty; all target ports are denied")
		} else {
			logging.Infof("security policy: allowed target ports whitelist: %s", formatAllowedPorts(policy.AllowedPorts))
		}
	}
}

func formatAllowedPorts(ports map[int]bool) string {
	if len(ports) == 0 {
		return ""
	}
	sorted := make([]int, 0, len(ports))
	for port := range ports {
		sorted = append(sorted, port)
	}
	sort.Ints(sorted)

	var out strings.Builder
	rangeStart := sorted[0]
	previous := sorted[0]
	flush := func(end int) {
		if out.Len() > 0 {
			out.WriteByte(',')
		}
		if rangeStart == end {
			fmt.Fprintf(&out, "%d", rangeStart)
			return
		}
		fmt.Fprintf(&out, "%d-%d", rangeStart, end)
	}
	for _, port := range sorted[1:] {
		if port != previous+1 {
			flush(previous)
			rangeStart = port
		}
		previous = port
	}
	flush(previous)
	return out.String()
}
