// Package authz implements the authorization decision engine.
package authz

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/danielvolz/docker-permission-proxy/internal/cache"
	"github.com/danielvolz/docker-permission-proxy/internal/classifier"
	"github.com/danielvolz/docker-permission-proxy/internal/config"
)

// ContainerMeta holds the subset of container inspect data we need for matching.
type ContainerMeta struct {
	ID          string
	Name        string
	Image       string
	Labels      map[string]string
	DefaultUser string
}

// Engine is the authorization engine that evaluates rules against requests.
type Engine struct {
	rules         []*config.Rule
	defaultPolicy string
	metaCache     *cache.TTLCache[*ContainerMeta]
	execCache     *cache.TTLCache[string] // exec-id → container-id
	upstream      string
	client        *http.Client
}

// NewEngine creates a new authorization engine.
func NewEngine(cfg *config.Config) *Engine {
	return &Engine{
		rules:         cfg.Rules,
		defaultPolicy: cfg.Default,
		metaCache:     cache.New[*ContainerMeta](5*time.Second, 1000),
		execCache:     cache.New[string](5*time.Minute, 10000),
		upstream:      cfg.Upstream,
		client:        newUpstreamClient(cfg.Upstream),
	}
}

// Decision represents an authorization decision.
type Decision struct {
	Allowed bool
	Reason  string
}

// Authorize makes an authorization decision for the given request.
func (e *Engine) Authorize(req *http.Request, class classifier.Classification, body []byte) Decision {
	// System actions (ping, version, info, events, df) are always allowed
	if class.Target == "system" {
		return Decision{Allowed: true, Reason: "system endpoint"}
	}

	// Explicitly deny unclassified/unknown actions regardless of default policy
	if class.Action == "unknown" {
		return Decision{Allowed: false, Reason: "unrecognized API endpoint"}
	}

	// Track if this is a follow-up exec request (start/resize/inspect)
	// where user validation was already done at exec create time
	isExecFollowup := false

	// For exec.start and exec.resize, resolve exec-id to container-id first
	if class.Action == "exec.start" || class.Action == "exec.resize" {
		containerID, ok := e.execCache.Get(class.ID)
		if !ok {
			return Decision{Allowed: false, Reason: "unknown exec id"}
		}
		// Re-check with the original exec rules
		class.Action = "exec"
		class.ID = containerID
		isExecFollowup = true
	}

	// For exec.inspect, also resolve and check
	if class.Action == "exec.inspect" {
		containerID, ok := e.execCache.Get(class.ID)
		if !ok {
			return Decision{Allowed: false, Reason: "unknown exec id"}
		}
		class.ID = containerID
		class.Action = "exec"
		isExecFollowup = true
	}

	// Find static rules that match action + target. Container-label rules are
	// added after inspecting the target container so they stay container-scoped.
	matchingRules := e.findRules(class.Action, class.Target)

	// Parse body for create/exec actions
	var bodyMap map[string]interface{}
	if len(body) > 0 {
		_ = json.Unmarshal(body, &bodyMap)
	}

	for _, rule := range matchingRules {
		if ruleNeedsContainerMeta(rule, class) {
			continue
		}
		if e.ruleAllows(rule, nil, bodyMap, class, isExecFollowup) {
			return Decision{Allowed: true, Reason: fmt.Sprintf("rule %q matched", rule.Name)}
		}
	}

	if len(matchingRules) == 0 && class.Action != "exec" && e.defaultPolicy == "allow" {
		return Decision{Allowed: true, Reason: "default policy: allow"}
	}

	// Get container metadata only when container selectors need it.
	var meta *ContainerMeta
	var labelRuleErr error
	if e.needsContainerMeta(matchingRules, class) {
		var err error
		meta, err = e.getContainerMeta(class.ID)
		if err != nil {
			log.Printf("WARN: failed to inspect %s: %v", class.ID, err)
			return Decision{Allowed: false, Reason: "failed to inspect target"}
		}

		labelRules, err := config.ParseContainerLabelRules(meta.Labels)
		if err != nil {
			labelRuleErr = err
		} else {
			matchingRules = append(matchingRules, matchingContainerLabelRules(labelRules, class.Action, class.Target)...)
		}
	}

	if len(matchingRules) == 0 {
		if labelRuleErr != nil {
			return Decision{Allowed: false, Reason: fmt.Sprintf("invalid container label rule: %v", labelRuleErr)}
		}
		if class.Action == "exec" {
			return Decision{Allowed: false, Reason: "exec requires explicit rule"}
		}
		if e.defaultPolicy == "allow" {
			return Decision{Allowed: true, Reason: "default policy: allow"}
		}
		return Decision{Allowed: false, Reason: fmt.Sprintf("no rules for action=%s target=%s", class.Action, class.Target)}
	}

	// Evaluate rules (ORed)
	for _, rule := range matchingRules {
		if e.ruleAllows(rule, meta, bodyMap, class, isExecFollowup) {
			return Decision{Allowed: true, Reason: fmt.Sprintf("rule %q matched", rule.Name)}
		}
	}

	if labelRuleErr != nil {
		return Decision{Allowed: false, Reason: fmt.Sprintf("invalid container label rule: %v", labelRuleErr)}
	}

	return Decision{Allowed: false, Reason: "no rule matched"}
}

func (e *Engine) needsContainerMeta(rules []*config.Rule, class classifier.Classification) bool {
	if class.Target != "container" || class.ID == "" || class.Action == "create" {
		return false
	}
	if class.Action == "list" || class.Action == "prune" {
		return false
	}
	if len(rules) == 0 || class.Action == "exec" {
		return true
	}
	for _, rule := range rules {
		if ruleNeedsContainerMeta(rule, class) {
			return true
		}
	}
	return false
}

// StoreExecID caches an exec-id → container-id mapping.
func (e *Engine) StoreExecID(execID, containerID string) {
	e.execCache.Set(execID, containerID)
}

// findRules returns rules that have the given action and target.
func (e *Engine) findRules(action, target string) []*config.Rule {
	var result []*config.Rule
	for _, r := range e.rules {
		if r.HasAction(action) && r.HasTarget(target) {
			result = append(result, r)
		}
	}
	return result
}

func matchingContainerLabelRules(rules []*config.Rule, action, target string) []*config.Rule {
	var result []*config.Rule
	for _, r := range rules {
		if r.HasAction(action) && r.HasTarget(target) {
			result = append(result, r)
		}
	}
	return result
}

func ruleNeedsContainerMeta(rule *config.Rule, class classifier.Classification) bool {
	return class.Action != "create" && class.Target == "container" && class.ID != "" && !rule.MatchAny
}

func (e *Engine) ruleAllows(rule *config.Rule, meta *ContainerMeta, body map[string]interface{}, class classifier.Classification, isExecFollowup bool) bool {
	if !e.ruleMatches(rule, meta, body, class) {
		return false
	}

	if class.Action == "exec" && !isExecFollowup {
		return e.checkExecUser(rule, meta, body)
	}

	return true
}

// ruleMatches checks if a rule's selectors match the given metadata/body.
func (e *Engine) ruleMatches(rule *config.Rule, meta *ContainerMeta, body map[string]interface{}, class classifier.Classification) bool {
	// MatchAny means the rule matches everything
	if rule.MatchAny {
		return true
	}

	// For "create" action, match against body fields
	if class.Action == "create" {
		return e.matchCreateBody(rule, body)
	}

	// If we need metadata but don't have it, fail
	if meta == nil {
		return false
	}

	// All selectors must match (ANDed)
	if len(rule.MatchLabels) > 0 {
		for k, pattern := range rule.MatchLabels {
			labelVal, exists := meta.Labels[k]
			if !exists {
				return false
			}
			if !globMatch(pattern, labelVal) {
				return false
			}
		}
	}

	if rule.MatchName != "" {
		name := strings.TrimPrefix(meta.Name, "/")
		if !globMatch(rule.MatchName, name) {
			return false
		}
	}

	if rule.MatchImage != "" {
		if !globMatch(rule.MatchImage, meta.Image) {
			return false
		}
	}

	if rule.MatchID != "" {
		if !strings.HasPrefix(meta.ID, rule.MatchID) {
			return false
		}
	}

	return true
}

// matchCreateBody matches a create action against body fields.
func (e *Engine) matchCreateBody(rule *config.Rule, body map[string]interface{}) bool {
	if body == nil {
		return false
	}

	if rule.MatchImage != "" {
		image, _ := body["Image"].(string)
		if !globMatch(rule.MatchImage, image) {
			return false
		}
	}

	if len(rule.MatchLabels) > 0 {
		labels := extractLabelsFromBody(body)
		for k, pattern := range rule.MatchLabels {
			labelVal, exists := labels[k]
			if !exists {
				return false
			}
			if !globMatch(pattern, labelVal) {
				return false
			}
		}
	}

	return true
}

// checkExecUser validates the exec body's User field against the rule.
func (e *Engine) checkExecUser(rule *config.Rule, meta *ContainerMeta, body map[string]interface{}) bool {
	if body == nil {
		return false
	}

	user, _ := body["User"].(string)

	// Empty/missing User inherits Docker's configured container user. Only allow
	// that inheritance when inspect exposes a safe, explicit non-root default.
	if user == "" {
		if meta == nil || meta.DefaultUser == "" {
			return false
		}
		user = meta.DefaultUser
	}

	// Parse user:group format. Docker accepts both names and numeric IDs.
	userPart := user
	groupPart := ""
	if idx := strings.IndexByte(user, ':'); idx >= 0 {
		userPart = user[:idx]
		groupPart = user[idx+1:]
	}

	// Always block root user/group regardless of rules (UID/GID 0 or name "root").
	if userPart == "0" || userPart == "root" || groupPart == "0" || groupPart == "root" {
		return false
	}

	// If ExecUser is set, exact match required.
	if rule.ExecUser != "" {
		return user == rule.ExecUser
	}

	// If ExecUserAllow is set, user must be in whitelist
	if len(rule.ExecUserAllow) > 0 {
		return rule.ExecUserAllow[userPart]
	}

	// No exec user config means exec is denied (safer default)
	return false
}

// getContainerMeta fetches or caches container inspect data.
func (e *Engine) getContainerMeta(id string) (*ContainerMeta, error) {
	if meta, ok := e.metaCache.Get(id); ok {
		return meta, nil
	}

	meta, err := e.inspectContainer(id)
	if err != nil {
		return nil, err
	}

	e.metaCache.Set(id, meta)
	return meta, nil
}

// inspectContainer fetches container metadata from the upstream Docker socket.
func (e *Engine) inspectContainer(id string) (*ContainerMeta, error) {
	url := fmt.Sprintf("%s/containers/%s/json", upstreamURL(e.upstream), id)

	resp, err := e.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("inspect request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("inspect returned status %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20)) // 5MB limit
	if err != nil {
		return nil, fmt.Errorf("reading inspect body: %w", err)
	}

	var data struct {
		ID     string `json:"Id"`
		Name   string `json:"Name"`
		Config struct {
			Image  string            `json:"Image"`
			Labels map[string]string `json:"Labels"`
			User   string            `json:"User"`
		} `json:"Config"`
	}
	if err := json.Unmarshal(bodyBytes, &data); err != nil {
		return nil, fmt.Errorf("parsing inspect json: %w", err)
	}

	return &ContainerMeta{
		ID:          data.ID,
		Name:        data.Name,
		Image:       data.Config.Image,
		Labels:      data.Config.Labels,
		DefaultUser: data.Config.User,
	}, nil
}

// extractLabelsFromBody extracts labels from a container create body.
func extractLabelsFromBody(body map[string]interface{}) map[string]string {
	labels := map[string]string{}

	// Labels can be at top level or under Config
	if l, ok := body["Labels"].(map[string]interface{}); ok {
		for k, v := range l {
			if s, ok := v.(string); ok {
				labels[k] = s
			}
		}
	}

	return labels
}

// globMatch performs glob matching supporting *, ? and character class wildcards.
// Unlike filepath.Match, it does not treat '/' as a special separator, so patterns
// like "registry.acme.io/*" work correctly against values with slashes.
func globMatch(pattern, value string) bool {
	// Use recursive matching that handles *, ?, and [] without treating / specially.
	return deepMatch(pattern, value)
}

// deepMatch performs recursive wildcard matching.
// '*' matches any sequence of characters (including empty), '?' matches exactly one character,
// and character classes [abc] are supported. '/' is not treated specially.
func deepMatch(pattern, value string) bool {
	for len(pattern) > 0 {
		switch pattern[0] {
		case '*':
			// Skip consecutive stars
			for len(pattern) > 0 && pattern[0] == '*' {
				pattern = pattern[1:]
			}
			// Trailing * matches everything
			if len(pattern) == 0 {
				return true
			}
			// Try matching the rest of the pattern at each position in value
			for i := 0; i <= len(value); i++ {
				if deepMatch(pattern, value[i:]) {
					return true
				}
			}
			return false
		case '?':
			if len(value) == 0 {
				return false
			}
			value = value[1:]
			pattern = pattern[1:]
		case '[':
			if len(value) == 0 {
				return false
			}
			// Use filepath.Match for the single-character class matching
			// Find the closing ]
			end := strings.IndexByte(pattern, ']')
			if end < 0 {
				// Malformed pattern — fail closed
				return false
			}
			charClass := pattern[:end+1]
			// Use filepath.Match with pattern "charClass" against single char
			matched, err := filepath.Match(charClass, string(value[0]))
			if err != nil || !matched {
				return false
			}
			pattern = pattern[end+1:]
			value = value[1:]
		case '\\':
			// Escaped character
			pattern = pattern[1:]
			if len(pattern) == 0 {
				return false
			}
			if len(value) == 0 || value[0] != pattern[0] {
				return false
			}
			value = value[1:]
			pattern = pattern[1:]
		default:
			if len(value) == 0 || value[0] != pattern[0] {
				return false
			}
			value = value[1:]
			pattern = pattern[1:]
		}
	}
	return len(value) == 0
}
