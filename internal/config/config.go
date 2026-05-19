// Package config parses DPP_RULE_* environment variables into Rule structs.
package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

// Config holds the parsed proxy configuration.
type Config struct {
	Listen         string        // DPP_LISTEN (e.g. "unix:///tmp/proxy.sock" or "tcp://0.0.0.0:2375")
	Upstream       string        // DPP_UPSTREAM (e.g. "unix:///var/run/docker.sock")
	Default        string        // DPP_DEFAULT ("deny", "allow", or "ask")
	ConfirmTimeout time.Duration // DPP_CONFIRM_TIMEOUT (default: 30s)
	Rules          []*Rule
}

// Rule represents a single permission rule parsed from DPP_RULE_<name>_* env vars.
type Rule struct {
	Name          string
	Decision      string            // allow, deny, or ask (default: allow)
	Actions       map[string]bool   // set of Docker action names
	Targets       map[string]bool   // set of resource types (default: container)
	MatchAny      bool              // MATCH=* means match everything
	MatchLabels   map[string]string // label key → value/glob
	MatchName     string            // glob pattern for container name
	MatchImage    string            // glob pattern for image
	MatchID       string            // sha prefix
	ExecUser      string            // required exact user for exec
	ExecUserAllow map[string]bool   // whitelist of allowed users for exec
}

var ruleEnvRe = regexp.MustCompile(`^DPP_RULE_([^_]+)_(.+)$`)

const ruleLabelPrefix = "dpp.rule."

const (
	DecisionAllow = "allow"
	DecisionDeny  = "deny"
	DecisionAsk   = "ask"
)

// Parse reads environment variables and returns a Config.
func Parse() (*Config, error) {
	cfg := &Config{
		Listen:         getEnv("DPP_LISTEN", "tcp://127.0.0.1:2375"),
		Upstream:       getEnv("DPP_UPSTREAM", "unix:///var/run/docker.sock"),
		Default:        getEnv("DPP_DEFAULT", "deny"),
		ConfirmTimeout: 30 * time.Second,
	}

	if cfg.Default != DecisionAllow && cfg.Default != DecisionDeny && cfg.Default != DecisionAsk {
		return nil, fmt.Errorf("DPP_DEFAULT must be %q, %q, or %q, got %q", DecisionAllow, DecisionDeny, DecisionAsk, cfg.Default)
	}
	if timeout := getEnv("DPP_CONFIRM_TIMEOUT", ""); timeout != "" {
		parsed, err := time.ParseDuration(timeout)
		if err != nil {
			return nil, fmt.Errorf("DPP_CONFIRM_TIMEOUT must be a Go duration like \"30s\", got %q", timeout)
		}
		if parsed <= 0 {
			return nil, fmt.Errorf("DPP_CONFIRM_TIMEOUT must be greater than zero, got %q", timeout)
		}
		cfg.ConfirmTimeout = parsed
	}

	builders := map[string]*ruleBuilder{}

	for _, kv := range os.Environ() {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}

		addEnvRuleField(builders, k, v)
	}

	rules, err := buildRules(builders)
	if err != nil {
		return nil, err
	}
	cfg.Rules = rules

	return cfg, nil
}

// ParseContainerLabelRules parses rules declared on Docker container labels.
// Label-defined rules are meant to be evaluated only for the container carrying
// those labels; callers enforce that scope by parsing labels from the inspected
// target container.
func ParseContainerLabelRules(labels map[string]string) ([]*Rule, error) {
	builders := map[string]*ruleBuilder{}

	for k, v := range labels {
		addContainerLabelRuleField(builders, k, v)
	}

	return buildRules(builders)
}

func addEnvRuleField(builders map[string]*ruleBuilder, key, value string) bool {
	m := ruleEnvRe.FindStringSubmatch(key)
	if m == nil {
		return false
	}

	name := strings.ToLower(m[1])
	field := m[2]
	setRuleBuilderField(builders, name, field, value)
	return true
}

func addContainerLabelRuleField(builders map[string]*ruleBuilder, key, value string) bool {
	if !strings.HasPrefix(key, ruleLabelPrefix) {
		return false
	}

	rest := key[len(ruleLabelPrefix):]
	name, field, ok := strings.Cut(rest, ".")
	if !ok || name == "" || field == "" {
		setRuleBuilderField(builders, "invalidlabel", key, value)
		return true
	}

	ruleField, ok := containerLabelRuleField(field)
	if !ok {
		setRuleBuilderField(builders, strings.ToLower(name), field, value)
		return true
	}

	setRuleBuilderField(builders, strings.ToLower(name), ruleField, value)
	return true
}

func containerLabelRuleField(field string) (string, bool) {
	lower := strings.ToLower(field)
	if strings.HasPrefix(lower, "match-label.") {
		return "MATCH_LABEL_" + field[len("match-label."):], true
	}

	switch lower {
	case "action":
		return "ACTION", true
	case "decision":
		return "DECISION", true
	case "target":
		return "TARGET", true
	case "match":
		return "MATCH", true
	case "match-name":
		return "MATCH_NAME", true
	case "match-image":
		return "MATCH_IMAGE", true
	case "match-id":
		return "MATCH_ID", true
	case "exec-user":
		return "EXEC_USER", true
	case "exec-user-allow":
		return "EXEC_USER_ALLOW", true
	default:
		return "", false
	}
}

func setRuleBuilderField(builders map[string]*ruleBuilder, name, field, value string) {
	rb, exists := builders[name]
	if !exists {
		rb = &ruleBuilder{name: name}
		builders[name] = rb
	}
	rb.set(field, value)
}

func buildRules(builders map[string]*ruleBuilder) ([]*Rule, error) {
	var rules []*Rule
	for _, rb := range builders {
		rule, err := rb.build()
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", rb.name, err)
		}
		if rule != nil {
			rules = append(rules, rule)
		}
	}
	return rules, nil
}

type ruleBuilder struct {
	name          string
	decision      string
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
	case upper == "DECISION":
		rb.decision = value
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

	decision := strings.ToLower(strings.TrimSpace(rb.decision))
	if decision == "" {
		decision = DecisionAllow
	}
	switch decision {
	case DecisionAllow, DecisionDeny, DecisionAsk:
	default:
		return nil, fmt.Errorf("DECISION must be %q, %q, or %q, got %q", DecisionAllow, DecisionDeny, DecisionAsk, rb.decision)
	}

	rule := &Rule{
		Name:          rb.name,
		Decision:      decision,
		Actions:       parseCSVSet(rb.actions),
		Targets:       parseCSVSet(rb.targets),
		MatchAny:      rb.matchAny,
		MatchLabels:   rb.matchLabels,
		MatchName:     rb.matchName,
		MatchImage:    rb.matchImage,
		MatchID:       rb.matchID,
		ExecUser:      rb.execUser,
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
