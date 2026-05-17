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
	ID     string
	Name   string
	Image  string
	Labels map[string]string
}

// Engine is the authorization engine that evaluates rules against requests.
type Engine struct {
	rules         []*config.Rule
	defaultPolicy string
	metaCache     *cache.TTLCache[*ContainerMeta]
	execCache     *cache.TTLCache[string] // exec-id → container-id
	upstream      string
}

// NewEngine creates a new authorization engine.
func NewEngine(cfg *config.Config) *Engine {
	return &Engine{
		rules:         cfg.Rules,
		defaultPolicy: cfg.Default,
		metaCache:     cache.New[*ContainerMeta](5*time.Second, 1000),
		execCache:     cache.New[string](5*time.Minute, 10000),
		upstream:      cfg.Upstream,
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

	// Find rules that match action + target
	matchingRules := e.findRules(class.Action, class.Target)
	if len(matchingRules) == 0 {
		return Decision{Allowed: false, Reason: fmt.Sprintf("no rules for action=%s target=%s", class.Action, class.Target)}
	}

	// Get container metadata if we have an ID
	var meta *ContainerMeta
	if class.ID != "" && class.Action != "create" {
		var err error
		meta, err = e.getContainerMeta(class.ID)
		if err != nil {
			log.Printf("WARN: failed to inspect %s: %v", class.ID, err)
			return Decision{Allowed: false, Reason: "failed to inspect target"}
		}
	}

	// Parse body for create/exec actions
	var bodyMap map[string]interface{}
	if len(body) > 0 {
		_ = json.Unmarshal(body, &bodyMap)
	}

	// Evaluate rules (ORed)
	for _, rule := range matchingRules {
		if !e.ruleMatches(rule, meta, bodyMap, class) {
			continue
		}

		// Exec special case: require user validation (skip for followup requests)
		if class.Action == "exec" && !isExecFollowup {
			if !e.checkExecUser(rule, bodyMap) {
				continue
			}
		}

		return Decision{Allowed: true, Reason: fmt.Sprintf("rule %q matched", rule.Name)}
	}

	return Decision{Allowed: false, Reason: "no rule matched"}
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
func (e *Engine) checkExecUser(rule *config.Rule, body map[string]interface{}) bool {
	if body == nil {
		return false
	}

	user, _ := body["User"].(string)

	// Reject empty/missing User field (would inherit container default — usually root)
	if user == "" {
		return false
	}

	// If ExecUser is set, exact match required
	if rule.ExecUser != "" {
		return user == rule.ExecUser
	}

	// If ExecUserAllow is set, user must be in whitelist
	if len(rule.ExecUserAllow) > 0 {
		return rule.ExecUserAllow[user]
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
	client := upstreamClient(e.upstream)
	url := fmt.Sprintf("%s/containers/%s/json", upstreamURL(e.upstream), id)

	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("inspect request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("inspect returned status %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading inspect body: %w", err)
	}

	var data struct {
		ID     string `json:"Id"`
		Name   string `json:"Name"`
		Config struct {
			Image  string            `json:"Image"`
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	if err := json.Unmarshal(bodyBytes, &data); err != nil {
		return nil, fmt.Errorf("parsing inspect json: %w", err)
	}

	return &ContainerMeta{
		ID:     data.ID,
		Name:   data.Name,
		Image:  data.Config.Image,
		Labels: data.Config.Labels,
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

// globMatch performs a simple glob match supporting * and ? wildcards.
func globMatch(pattern, value string) bool {
	matched, err := filepath.Match(pattern, value)
	if err != nil {
		// If pattern is invalid, try prefix match for patterns like "registry.acme.io/*"
		// filepath.Match doesn't support ** or paths with /, so fall back to manual
		return strings.Contains(value, strings.ReplaceAll(pattern, "*", ""))
	}
	return matched
}
