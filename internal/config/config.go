// Package config parses DPP_RULE_* environment variables into Rule structs.
package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Config holds the parsed proxy configuration.
type Config struct {
	Listen   string // DPP_LISTEN (e.g. "unix:///tmp/proxy.sock" or "tcp://0.0.0.0:2375")
	Upstream string // DPP_UPSTREAM (e.g. "unix:///var/run/docker.sock")
	Default  string // DPP_DEFAULT ("deny" or "allow")
	Rules    []*Rule
}

// Rule represents a single permission rule parsed from DPP_RULE_<name>_* env vars.
type Rule struct {
	Name           string
	Actions        map[string]bool // set of allowed verbs
	Targets        map[string]bool // set of resource types (default: container)
	MatchAny       bool            // MATCH=* means match everything
	MatchLabels    map[string]string // label key → value/glob
	MatchName      string          // glob pattern for container name
	MatchImage     string          // glob pattern for image
	MatchID        string          // sha prefix
	ExecUser       string          // required exact user for exec
	ExecUserAllow  map[string]bool // whitelist of allowed users for exec
}

var ruleEnvRe = regexp.MustCompile(`^DPP_RULE_([^_]+)_(.+)$`)

// Parse reads environment variables and returns a Config.
func Parse() (*Config, error) {
	cfg := &Config{
		Listen:   getEnv("DPP_LISTEN", "tcp://127.0.0.1:2375"),
		Upstream: getEnv("DPP_UPSTREAM", "unix:///var/run/docker.sock"),
		Default:  getEnv("DPP_DEFAULT", "deny"),
	}

	if cfg.Default != "allow" && cfg.Default != "deny" {
		return nil, fmt.Errorf("DPP_DEFAULT must be \"allow\" or \"deny\", got %q", cfg.Default)
	}

	builders := map[string]*ruleBuilder{}

	for _, kv := range os.Environ() {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}

		m := ruleEnvRe.FindStringSubmatch(k)
		if m == nil {
			continue
		}

		name := strings.ToLower(m[1])
		field := m[2]

		rb, exists := builders[name]
		if !exists {
			rb = &ruleBuilder{name: name}
			builders[name] = rb
		}
		rb.set(field, v)
	}

	for _, rb := range builders {
		rule, err := rb.build()
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", rb.name, err)
		}
		if rule != nil {
			cfg.Rules = append(cfg.Rules, rule)
		}
	}

	return cfg, nil
}

type ruleBuilder struct {
	name          string
	actions       string
	targets       string
	matchAny      bool
	matchLabels   map[string]string
	matchName     string
	matchImage    string
	matchID       string
	execUser      string
	execUserAllow string
	unknownFields []string
}

func (rb *ruleBuilder) set(field, value string) {
	upper := strings.ToUpper(field)

	switch {
	case upper == "ACTION":
		rb.actions = value
	case upper == "TARGET":
		rb.targets = value
	case upper == "MATCH" && value == "*":
		rb.matchAny = true
	case strings.HasPrefix(upper, "MATCH_LABEL_"):
		// Extract label key preserving the original case from the env var field
		// (e.g. DPP_RULE_x_MATCH_LABEL_My.Label=val → key="My.Label")
		labelKey := field[len("MATCH_LABEL_"):]
		if rb.matchLabels == nil {
			rb.matchLabels = map[string]string{}
		}
		rb.matchLabels[labelKey] = value
	case upper == "MATCH_NAME":
		rb.matchName = value
	case upper == "MATCH_IMAGE":
		rb.matchImage = value
	case upper == "MATCH_ID":
		rb.matchID = value
	case upper == "EXEC_USER":
		rb.execUser = value
	case upper == "EXEC_USER_ALLOW":
		rb.execUserAllow = value
	default:
		rb.unknownFields = append(rb.unknownFields, field)
	}
}

func (rb *ruleBuilder) build() (*Rule, error) {
	if len(rb.unknownFields) > 0 {
		return nil, fmt.Errorf("unknown field(s): %s", strings.Join(rb.unknownFields, ","))
	}

	// Rule is only valid if ACTION is present
	if rb.actions == "" {
		return nil, nil
	}

	rule := &Rule{
		Name:        rb.name,
		Actions:     parseCSVSet(rb.actions),
		Targets:     parseCSVSet(rb.targets),
		MatchAny:    rb.matchAny,
		MatchLabels: rb.matchLabels,
		MatchName:   rb.matchName,
		MatchImage:  rb.matchImage,
		MatchID:     rb.matchID,
		ExecUser:    rb.execUser,
		ExecUserAllow: parseCSVSet(rb.execUserAllow),
	}

	// Default target is "container" if none specified
	if len(rule.Targets) == 0 {
		rule.Targets = map[string]bool{"container": true}
	}

	return rule, nil
}

func parseCSVSet(s string) map[string]bool {
	if s == "" {
		return nil
	}
	set := map[string]bool{}
	for _, item := range strings.Split(s, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			set[strings.ToLower(item)] = true
		}
	}
	return set
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// HasAction checks if a rule allows a given action.
func (r *Rule) HasAction(action string) bool {
	return r.Actions[action]
}

// HasTarget checks if a rule applies to a given target type.
func (r *Rule) HasTarget(target string) bool {
	return r.Targets[target]
}
