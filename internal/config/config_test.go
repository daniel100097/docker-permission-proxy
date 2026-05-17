package config

import (
	"os"
	"testing"
)

// helper to set env vars and clean up after test
func setEnvs(t *testing.T, envs map[string]string) {
	t.Helper()
	for k, v := range envs {
		os.Setenv(k, v)
		t.Cleanup(func() { os.Unsetenv(k) })
	}
}

func clearAllDPPEnvs(t *testing.T) {
	t.Helper()
	for _, kv := range os.Environ() {
		k := kv[:len(kv)-len(kv)+len(kv)]
		if idx := indexOf(kv, '='); idx > 0 {
			k = kv[:idx]
		}
		if len(k) > 4 && k[:4] == "DPP_" {
			os.Unsetenv(k)
			t.Cleanup(func() {})
		}
	}
}

func indexOf(s string, c byte) int {
	for i := range s {
		if s[i] == c {
			return i
		}
	}
	return -1
}

func TestParse_Defaults(t *testing.T) {
	clearAllDPPEnvs(t)

	cfg, err := Parse()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Listen != "tcp://127.0.0.1:2375" {
		t.Errorf("expected default listen tcp://127.0.0.1:2375, got %s", cfg.Listen)
	}
	if cfg.Upstream != "unix:///var/run/docker.sock" {
		t.Errorf("expected default upstream, got %s", cfg.Upstream)
	}
	if cfg.Default != "deny" {
		t.Errorf("expected default policy deny, got %s", cfg.Default)
	}
	if len(cfg.Rules) != 0 {
		t.Errorf("expected no rules by default, got %d", len(cfg.Rules))
	}
}

func TestParse_GlobalConfig(t *testing.T) {
	clearAllDPPEnvs(t)
	setEnvs(t, map[string]string{
		"DPP_LISTEN":   "unix:///tmp/test.sock",
		"DPP_UPSTREAM": "unix:///custom/docker.sock",
		"DPP_DEFAULT":  "allow",
	})

	cfg, err := Parse()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Listen != "unix:///tmp/test.sock" {
		t.Errorf("expected unix:///tmp/test.sock, got %s", cfg.Listen)
	}
	if cfg.Upstream != "unix:///custom/docker.sock" {
		t.Errorf("expected custom upstream, got %s", cfg.Upstream)
	}
	if cfg.Default != "allow" {
		t.Errorf("expected allow, got %s", cfg.Default)
	}
}

func TestParse_InvalidDefault(t *testing.T) {
	clearAllDPPEnvs(t)
	setEnvs(t, map[string]string{
		"DPP_DEFAULT": "yolo",
	})

	if _, err := Parse(); err == nil {
		t.Fatal("expected invalid DPP_DEFAULT to return error")
	}
}

func TestParse_SingleRule(t *testing.T) {
	clearAllDPPEnvs(t)
	setEnvs(t, map[string]string{
		"DPP_RULE_mytest_ACTION": "exec",
		"DPP_RULE_mytest_MATCH_LABEL_team": "dev",
		"DPP_RULE_mytest_EXEC_USER_ALLOW":  "1000,1001",
	})

	cfg, err := Parse()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(cfg.Rules))
	}

	r := cfg.Rules[0]
	if r.Name != "mytest" {
		t.Errorf("expected rule name mytest, got %s", r.Name)
	}
	if !r.HasAction("exec") {
		t.Error("expected rule to have exec action")
	}
	if r.HasAction("start") {
		t.Error("should not have start action")
	}
	if !r.HasTarget("container") {
		t.Error("expected default target container")
	}
	if r.MatchLabels["team"] != "dev" {
		t.Errorf("expected label team=dev, got %v", r.MatchLabels)
	}
	if !r.ExecUserAllow["1000"] || !r.ExecUserAllow["1001"] {
		t.Errorf("expected exec user allow 1000,1001, got %v", r.ExecUserAllow)
	}
}

func TestParse_MultipleRules(t *testing.T) {
	clearAllDPPEnvs(t)
	setEnvs(t, map[string]string{
		"DPP_RULE_alpha_ACTION":          "list,inspect",
		"DPP_RULE_alpha_TARGET":          "container,image",
		"DPP_RULE_alpha_MATCH":           "*",
		"DPP_RULE_beta_ACTION":           "start,stop,restart",
		"DPP_RULE_beta_MATCH_LABEL_env":  "prod",
		"DPP_RULE_gamma_ACTION":          "exec",
		"DPP_RULE_gamma_MATCH_NAME":      "worker-*",
		"DPP_RULE_gamma_EXEC_USER":       "1000",
	})

	cfg, err := Parse()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.Rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(cfg.Rules))
	}

	// Find rules by name
	ruleMap := map[string]*Rule{}
	for _, r := range cfg.Rules {
		ruleMap[r.Name] = r
	}

	// Alpha rule
	alpha := ruleMap["alpha"]
	if alpha == nil {
		t.Fatal("missing alpha rule")
	}
	if !alpha.HasAction("list") || !alpha.HasAction("inspect") {
		t.Error("alpha should have list,inspect")
	}
	if !alpha.HasTarget("container") || !alpha.HasTarget("image") {
		t.Error("alpha should target container,image")
	}
	if !alpha.MatchAny {
		t.Error("alpha should have MatchAny=true")
	}

	// Beta rule
	beta := ruleMap["beta"]
	if beta == nil {
		t.Fatal("missing beta rule")
	}
	if !beta.HasAction("start") || !beta.HasAction("stop") || !beta.HasAction("restart") {
		t.Error("beta should have start,stop,restart")
	}
	if beta.MatchLabels["env"] != "prod" {
		t.Errorf("beta should match label env=prod, got %v", beta.MatchLabels)
	}

	// Gamma rule
	gamma := ruleMap["gamma"]
	if gamma == nil {
		t.Fatal("missing gamma rule")
	}
	if !gamma.HasAction("exec") {
		t.Error("gamma should have exec action")
	}
	if gamma.MatchName != "worker-*" {
		t.Errorf("gamma should match name worker-*, got %s", gamma.MatchName)
	}
	if gamma.ExecUser != "1000" {
		t.Errorf("gamma exec user should be 1000, got %s", gamma.ExecUser)
	}
}

func TestParse_RuleWithoutAction_Ignored(t *testing.T) {
	clearAllDPPEnvs(t)
	setEnvs(t, map[string]string{
		"DPP_RULE_nope_MATCH_LABEL_x": "y",
		"DPP_RULE_nope_TARGET":        "container",
	})

	cfg, err := Parse()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.Rules) != 0 {
		t.Errorf("rule without ACTION should be ignored, got %d rules", len(cfg.Rules))
	}
}

func TestParse_UnknownRuleField_ReturnsError(t *testing.T) {
	clearAllDPPEnvs(t)
	setEnvs(t, map[string]string{
		"DPP_RULE_bad_ACTION": "start",
		"DPP_RULE_bad_ACTON":  "stop",
	})

	if _, err := Parse(); err == nil {
		t.Fatal("expected unknown field to return error")
	}
}

func TestParse_RuleNameWithUnderscore_ReturnsError(t *testing.T) {
	clearAllDPPEnvs(t)
	setEnvs(t, map[string]string{
		"DPP_RULE_read_all_ACTION": "list",
	})

	if _, err := Parse(); err == nil {
		t.Fatal("expected underscore in rule name to return error")
	}
}

func TestParse_MatchImage(t *testing.T) {
	clearAllDPPEnvs(t)
	setEnvs(t, map[string]string{
		"DPP_RULE_imgtest_ACTION":      "create",
		"DPP_RULE_imgtest_MATCH_IMAGE": "registry.acme.io/*",
	})

	cfg, err := Parse()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(cfg.Rules))
	}

	r := cfg.Rules[0]
	if r.MatchImage != "registry.acme.io/*" {
		t.Errorf("expected image glob, got %s", r.MatchImage)
	}
}

func TestParse_MatchID(t *testing.T) {
	clearAllDPPEnvs(t)
	setEnvs(t, map[string]string{
		"DPP_RULE_idtest_ACTION":   "inspect",
		"DPP_RULE_idtest_MATCH_ID": "abc123",
	})

	cfg, err := Parse()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(cfg.Rules))
	}

	r := cfg.Rules[0]
	if r.MatchID != "abc123" {
		t.Errorf("expected match ID abc123, got %s", r.MatchID)
	}
}

func TestParse_MultipleLabels(t *testing.T) {
	clearAllDPPEnvs(t)
	setEnvs(t, map[string]string{
		"DPP_RULE_multi_ACTION":           "exec",
		"DPP_RULE_multi_MATCH_LABEL_team": "dev",
		"DPP_RULE_multi_MATCH_LABEL_tier": "frontend",
		"DPP_RULE_multi_EXEC_USER_ALLOW":  "app",
	})

	cfg, err := Parse()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(cfg.Rules))
	}

	r := cfg.Rules[0]
	if len(r.MatchLabels) != 2 {
		t.Errorf("expected 2 match labels, got %d", len(r.MatchLabels))
	}
	if r.MatchLabels["team"] != "dev" {
		t.Errorf("expected team=dev")
	}
	if r.MatchLabels["tier"] != "frontend" {
		t.Errorf("expected tier=frontend")
	}
}

func TestParse_LabelKeyCasePreserved(t *testing.T) {
	clearAllDPPEnvs(t)
	setEnvs(t, map[string]string{
		"DPP_RULE_labels_ACTION":                 "inspect",
		"DPP_RULE_labels_MATCH_LABEL_My.Label": "value",
	})

	cfg, err := Parse()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(cfg.Rules))
	}
	if got := cfg.Rules[0].MatchLabels["My.Label"]; got != "value" {
		t.Errorf("expected preserved label key My.Label=value, got %v", cfg.Rules[0].MatchLabels)
	}
}

func TestParse_CaseInsensitiveActions(t *testing.T) {
	clearAllDPPEnvs(t)
	setEnvs(t, map[string]string{
		"DPP_RULE_casetest_ACTION": "LIST,Inspect,LOGS",
	})

	cfg, err := Parse()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(cfg.Rules))
	}

	r := cfg.Rules[0]
	if !r.HasAction("list") || !r.HasAction("inspect") || !r.HasAction("logs") {
		t.Errorf("expected case-insensitive actions, got %v", r.Actions)
	}
}

func TestParse_CSVWithSpaces(t *testing.T) {
	clearAllDPPEnvs(t)
	setEnvs(t, map[string]string{
		"DPP_RULE_spaces_ACTION":          "start , stop , restart",
		"DPP_RULE_spaces_EXEC_USER_ALLOW": "1000 , deploy , 1001",
	})

	cfg, err := Parse()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(cfg.Rules))
	}

	r := cfg.Rules[0]
	if !r.HasAction("start") || !r.HasAction("stop") || !r.HasAction("restart") {
		t.Errorf("expected trimmed actions, got %v", r.Actions)
	}
	if !r.ExecUserAllow["1000"] || !r.ExecUserAllow["deploy"] || !r.ExecUserAllow["1001"] {
		t.Errorf("expected trimmed users, got %v", r.ExecUserAllow)
	}
}

func TestParseCSVSet_Empty(t *testing.T) {
	result := parseCSVSet("")
	if result != nil {
		t.Errorf("expected nil for empty string, got %v", result)
	}
}

func TestParseCSVSet_Single(t *testing.T) {
	result := parseCSVSet("exec")
	if len(result) != 1 || !result["exec"] {
		t.Errorf("expected {exec: true}, got %v", result)
	}
}

func TestParseCSVSet_Multiple(t *testing.T) {
	result := parseCSVSet("start,stop,restart")
	if len(result) != 3 {
		t.Errorf("expected 3 items, got %d", len(result))
	}
	for _, action := range []string{"start", "stop", "restart"} {
		if !result[action] {
			t.Errorf("expected %s in set", action)
		}
	}
}

func TestRule_HasAction(t *testing.T) {
	r := &Rule{Actions: map[string]bool{"exec": true, "list": true}}
	if !r.HasAction("exec") {
		t.Error("expected HasAction exec = true")
	}
	if r.HasAction("start") {
		t.Error("expected HasAction start = false")
	}
}

func TestRule_HasTarget(t *testing.T) {
	r := &Rule{Targets: map[string]bool{"container": true, "image": true}}
	if !r.HasTarget("container") {
		t.Error("expected HasTarget container = true")
	}
	if r.HasTarget("network") {
		t.Error("expected HasTarget network = false")
	}
}
