package tunnel

import (
	"fmt"
	"strconv"

	"github.com/wsyzxjn/uulink/pkg/auth"
)

// CLIMapping holds the command-line mapping flags that accompany configured
// mappings. Every field is optional.
type CLIMapping struct {
	RuleID     string // -rule-id
	Mapping    string // -mapping LOCAL:REMOTE (single ports or ranges)
	LocalHost  string // -local-host
	LocalPort  string // -local (port or range)
	RemoteHost string // -remote-host
	RemotePort string // -remote-port (port or range)
}

// BuildRules expands configured mappings followed by the command-line
// mapping flags into listener rules. A rule without an ID gets a random
// numeric one; ranges always get generated IDs so every port is unique.
func BuildRules(mappings []auth.PortMapping, cli CLIMapping) ([]Rule, error) {
	var rules []Rule
	seen := make(map[string]bool)

	appendRule := func(rule Rule) error {
		if rule.ID == "" {
			rule.ID = GenerateRuleID()
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
	appendPairs := func(pairs []PortPair, ruleID, localHost, remoteHost string) error {
		for _, pair := range pairs {
			id := ruleID
			if len(pairs) > 1 {
				id = "" // generate unique numeric rule IDs across ranges
			}
			if err := appendRule(Rule{
				ID:         id,
				LocalHost:  localHost,
				LocalPort:  pair.LocalPort,
				TargetHost: remoteHost,
				TargetPort: pair.RemotePort,
			}); err != nil {
				return err
			}
		}
		return nil
	}

	for _, mapping := range mappings {
		localHost := mapping.LocalHost
		if localHost == "" {
			localHost = "127.0.0.1"
		}
		remoteHost := mapping.RemoteHost
		if remoteHost == "" {
			remoteHost = "127.0.0.1"
		}

		var pairs []PortPair
		var err error
		switch {
		case mapping.Range != "":
			pairs, err = ParsePortMappingSpec(mapping.Range)
		case mapping.LocalRange != "" || mapping.RemoteRange != "":
			localSpec := mapping.LocalRange
			if localSpec == "" && mapping.LocalPort != 0 {
				localSpec = strconv.Itoa(mapping.LocalPort)
			}
			remoteSpec := mapping.RemoteRange
			if remoteSpec == "" && mapping.RemotePort != 0 {
				remoteSpec = strconv.Itoa(mapping.RemotePort)
			}
			pairs, err = ExpandPortRange(localSpec, remoteSpec)
		case mapping.LocalPort != 0 && mapping.RemotePort != 0:
			pairs = []PortPair{{LocalPort: mapping.LocalPort, RemotePort: mapping.RemotePort}}
		default:
			return nil, fmt.Errorf("mapping must specify local and remote ports or ranges")
		}
		if err != nil {
			return nil, fmt.Errorf("mapping rule: %w", err)
		}
		if err := appendPairs(pairs, mapping.RuleID, localHost, remoteHost); err != nil {
			return nil, err
		}
	}

	if cli.Mapping != "" {
		pairs, err := ParsePortMappingSpec(cli.Mapping)
		if err != nil {
			return nil, fmt.Errorf("-mapping: %w", err)
		}
		if err := appendPairs(pairs, cli.RuleID, cli.LocalHost, cli.RemoteHost); err != nil {
			return nil, err
		}
	}

	if cli.LocalPort != "" || cli.RemotePort != "" {
		if cli.LocalPort == "" || cli.RemotePort == "" {
			return nil, fmt.Errorf("both -local and -remote-port are required for a command-line mapping")
		}
		if len(mappings) > 0 && cli.RuleID != "" {
			return nil, fmt.Errorf("-rule-id cannot be applied globally when config mappings define their own rule_id")
		}
		pairs, err := ExpandPortRange(cli.LocalPort, cli.RemotePort)
		if err != nil {
			return nil, fmt.Errorf("cli port mapping: %w", err)
		}
		if err := appendPairs(pairs, cli.RuleID, cli.LocalHost, cli.RemoteHost); err != nil {
			return nil, err
		}
	}
	return rules, nil
}
