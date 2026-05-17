package authz

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/danielvolz/docker-permission-proxy/internal/classifier"
	"github.com/danielvolz/docker-permission-proxy/internal/config"
)

// mockDockerServer simulates the Docker daemon for testing container inspect.
func mockDockerServer(containers map[string]map[string]interface{}) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Match /containers/{id}/json
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 3 && parts[0] == "containers" && parts[2] == "json" {
			id := parts[1]
			if data, ok := containers[id]; ok {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(data)
				return
			}
			http.NotFound(w, r)
			return
		}
		http.NotFound(w, r)
	}))
}

// newTestEngine creates an Engine for testing with a mock upstream.
func newTestEngine(rules []*config.Rule, dockerURL string) *Engine {
	cfg := &config.Config{
		Rules:    rules,
		Default:  "deny",
		Upstream: dockerURL,
	}
	e := NewEngine(cfg)
	// Override the metadata cache inspection to use the test server
	return e
}

func TestEngine_SystemAlwaysAllowed(t *testing.T) {
	cfg := &config.Config{Rules: nil, Default: "deny", Upstream: "unix:///var/run/docker.sock"}
	e := NewEngine(cfg)

	systemActions := []string{"ping", "version", "info", "events", "df"}
	for _, action := range systemActions {
		t.Run(action, func(t *testing.T) {
			class := classifier.Classification{Action: action, Target: "system"}
			req := httptest.NewRequest("GET", "/"+action, nil)
			decision := e.Authorize(req, class, nil)
			if !decision.Allowed {
				t.Errorf("expected system action %s to be allowed, got denied: %s", action, decision.Reason)
			}
		})
	}
}

func TestEngine_NoRules_DenyAll(t *testing.T) {
	cfg := &config.Config{Rules: nil, Default: "deny", Upstream: "unix:///var/run/docker.sock"}
	e := NewEngine(cfg)

	class := classifier.Classification{Action: "list", Target: "container"}
	req := httptest.NewRequest("GET", "/containers/json", nil)
	decision := e.Authorize(req, class, nil)
	if decision.Allowed {
		t.Error("expected deny with no rules")
	}
}

func TestEngine_MatchAny_AllowsAll(t *testing.T) {
	rules := []*config.Rule{{
		Name:     "readall",
		Actions:  map[string]bool{"list": true, "inspect": true, "logs": true},
		Targets:  map[string]bool{"container": true},
		MatchAny: true,
	}}

	// Use a mock server for inspect calls
	containers := map[string]map[string]interface{}{
		"abc123": {
			"Id":   "abc123full",
			"Name": "/mycontainer",
			"Config": map[string]interface{}{
				"Image":  "nginx",
				"Labels": map[string]interface{}{"team": "dev"},
			},
		},
	}
	server := mockDockerServer(containers)
	defer server.Close()

	cfg := &config.Config{Rules: rules, Default: "deny", Upstream: server.URL}
	e := newTestEngineWithHTTP(cfg, server.URL)

	// list - no ID needed
	class := classifier.Classification{Action: "list", Target: "container"}
	req := httptest.NewRequest("GET", "/containers/json", nil)
	decision := e.Authorize(req, class, nil)
	if !decision.Allowed {
		t.Errorf("expected allow for list, got: %s", decision.Reason)
	}

	// inspect
	class = classifier.Classification{Action: "inspect", Target: "container", ID: "abc123"}
	req = httptest.NewRequest("GET", "/containers/abc123/json", nil)
	decision = e.Authorize(req, class, nil)
	if !decision.Allowed {
		t.Errorf("expected allow for inspect, got: %s", decision.Reason)
	}
}

func TestEngine_LabelMatch(t *testing.T) {
	rules := []*config.Rule{{
		Name:        "devexec",
		Actions:     map[string]bool{"start": true, "stop": true},
		Targets:     map[string]bool{"container": true},
		MatchLabels: map[string]string{"team": "dev"},
	}}

	containers := map[string]map[string]interface{}{
		"allowed": {
			"Id":   "allowedfull",
			"Name": "/dev-app",
			"Config": map[string]interface{}{
				"Image":  "myapp",
				"Labels": map[string]interface{}{"team": "dev"},
			},
		},
		"denied": {
			"Id":   "deniedfull",
			"Name": "/prod-app",
			"Config": map[string]interface{}{
				"Image":  "myapp",
				"Labels": map[string]interface{}{"team": "prod"},
			},
		},
	}
	server := mockDockerServer(containers)
	defer server.Close()

	cfg := &config.Config{Rules: rules, Default: "deny", Upstream: server.URL}
	e := newTestEngineWithHTTP(cfg, server.URL)

	// Allowed container
	class := classifier.Classification{Action: "start", Target: "container", ID: "allowed"}
	req := httptest.NewRequest("POST", "/containers/allowed/start", nil)
	decision := e.Authorize(req, class, nil)
	if !decision.Allowed {
		t.Errorf("expected allow for labeled container, got: %s", decision.Reason)
	}

	// Denied container
	class = classifier.Classification{Action: "start", Target: "container", ID: "denied"}
	req = httptest.NewRequest("POST", "/containers/denied/start", nil)
	decision = e.Authorize(req, class, nil)
	if decision.Allowed {
		t.Error("expected deny for container without matching label")
	}
}

func TestEngine_NameGlobMatch(t *testing.T) {
	rules := []*config.Rule{{
		Name:      "workers",
		Actions:   map[string]bool{"restart": true},
		Targets:   map[string]bool{"container": true},
		MatchName: "worker-*",
	}}

	containers := map[string]map[string]interface{}{
		"w1": {
			"Id":   "w1full",
			"Name": "/worker-01",
			"Config": map[string]interface{}{
				"Image":  "worker",
				"Labels": map[string]interface{}{},
			},
		},
		"w2": {
			"Id":   "w2full",
			"Name": "/api-server",
			"Config": map[string]interface{}{
				"Image":  "api",
				"Labels": map[string]interface{}{},
			},
		},
	}
	server := mockDockerServer(containers)
	defer server.Close()

	cfg := &config.Config{Rules: rules, Default: "deny", Upstream: server.URL}
	e := newTestEngineWithHTTP(cfg, server.URL)

	// worker-01 should match
	class := classifier.Classification{Action: "restart", Target: "container", ID: "w1"}
	req := httptest.NewRequest("POST", "/containers/w1/restart", nil)
	decision := e.Authorize(req, class, nil)
	if !decision.Allowed {
		t.Errorf("expected allow for worker-01, got: %s", decision.Reason)
	}

	// api-server should not match
	class = classifier.Classification{Action: "restart", Target: "container", ID: "w2"}
	req = httptest.NewRequest("POST", "/containers/w2/restart", nil)
	decision = e.Authorize(req, class, nil)
	if decision.Allowed {
		t.Error("expected deny for api-server (doesn't match worker-*)")
	}
}

func TestEngine_ImageGlobMatch(t *testing.T) {
	rules := []*config.Rule{{
		Name:       "acme",
		Actions:    map[string]bool{"stop": true},
		Targets:    map[string]bool{"container": true},
		MatchImage: "registry.acme.io/*",
	}}

	containers := map[string]map[string]interface{}{
		"c1": {
			"Id":   "c1full",
			"Name": "/acme-app",
			"Config": map[string]interface{}{
				"Image":  "registry.acme.io/myapp",
				"Labels": map[string]interface{}{},
			},
		},
		"c2": {
			"Id":   "c2full",
			"Name": "/other-app",
			"Config": map[string]interface{}{
				"Image":  "docker.io/library/nginx",
				"Labels": map[string]interface{}{},
			},
		},
	}
	server := mockDockerServer(containers)
	defer server.Close()

	cfg := &config.Config{Rules: rules, Default: "deny", Upstream: server.URL}
	e := newTestEngineWithHTTP(cfg, server.URL)

	// acme image should match
	class := classifier.Classification{Action: "stop", Target: "container", ID: "c1"}
	req := httptest.NewRequest("POST", "/containers/c1/stop", nil)
	decision := e.Authorize(req, class, nil)
	if !decision.Allowed {
		t.Errorf("expected allow for acme image, got: %s", decision.Reason)
	}

	// non-acme image should not match
	class = classifier.Classification{Action: "stop", Target: "container", ID: "c2"}
	req = httptest.NewRequest("POST", "/containers/c2/stop", nil)
	decision = e.Authorize(req, class, nil)
	if decision.Allowed {
		t.Error("expected deny for non-acme image")
	}
}

func TestEngine_IDPrefixMatch(t *testing.T) {
	rules := []*config.Rule{{
		Name:    "specific",
		Actions: map[string]bool{"kill": true},
		Targets: map[string]bool{"container": true},
		MatchID: "abc123",
	}}

	containers := map[string]map[string]interface{}{
		"abc": {
			"Id":   "abc123def456",
			"Name": "/specific-container",
			"Config": map[string]interface{}{
				"Image":  "myapp",
				"Labels": map[string]interface{}{},
			},
		},
		"xyz": {
			"Id":   "xyz789",
			"Name": "/other-container",
			"Config": map[string]interface{}{
				"Image":  "myapp",
				"Labels": map[string]interface{}{},
			},
		},
	}
	server := mockDockerServer(containers)
	defer server.Close()

	cfg := &config.Config{Rules: rules, Default: "deny", Upstream: server.URL}
	e := newTestEngineWithHTTP(cfg, server.URL)

	// Matching ID prefix
	class := classifier.Classification{Action: "kill", Target: "container", ID: "abc"}
	req := httptest.NewRequest("POST", "/containers/abc/kill", nil)
	decision := e.Authorize(req, class, nil)
	if !decision.Allowed {
		t.Errorf("expected allow for matching ID prefix, got: %s", decision.Reason)
	}

	// Non-matching ID
	class = classifier.Classification{Action: "kill", Target: "container", ID: "xyz"}
	req = httptest.NewRequest("POST", "/containers/xyz/kill", nil)
	decision = e.Authorize(req, class, nil)
	if decision.Allowed {
		t.Error("expected deny for non-matching ID prefix")
	}
}

func TestEngine_ExecUserExact(t *testing.T) {
	rules := []*config.Rule{{
		Name:        "devexec",
		Actions:     map[string]bool{"exec": true},
		Targets:     map[string]bool{"container": true},
		MatchLabels: map[string]string{"team": "dev"},
		ExecUser:    "1000",
	}}

	containers := map[string]map[string]interface{}{
		"dev1": {
			"Id":   "dev1full",
			"Name": "/dev-container",
			"Config": map[string]interface{}{
				"Image":  "myapp",
				"Labels": map[string]interface{}{"team": "dev"},
			},
		},
	}
	server := mockDockerServer(containers)
	defer server.Close()

	cfg := &config.Config{Rules: rules, Default: "deny", Upstream: server.URL}
	e := newTestEngineWithHTTP(cfg, server.URL)

	// Correct user
	body := []byte(`{"User": "1000", "Cmd": ["sh"]}`)
	class := classifier.Classification{Action: "exec", Target: "container", ID: "dev1"}
	req := httptest.NewRequest("POST", "/containers/dev1/exec", nil)
	decision := e.Authorize(req, class, body)
	if !decision.Allowed {
		t.Errorf("expected allow for correct exec user, got: %s", decision.Reason)
	}

	// Wrong user
	body = []byte(`{"User": "0", "Cmd": ["sh"]}`)
	decision = e.Authorize(req, class, body)
	if decision.Allowed {
		t.Error("expected deny for wrong exec user (root)")
	}

	// Empty user
	body = []byte(`{"Cmd": ["sh"]}`)
	decision = e.Authorize(req, class, body)
	if decision.Allowed {
		t.Error("expected deny for empty exec user")
	}

	// Missing user field entirely
	body = []byte(`{"User": "", "Cmd": ["sh"]}`)
	decision = e.Authorize(req, class, body)
	if decision.Allowed {
		t.Error("expected deny for empty string user")
	}
}

func TestEngine_ExecUserAllow(t *testing.T) {
	rules := []*config.Rule{{
		Name:          "devexec",
		Actions:       map[string]bool{"exec": true},
		Targets:       map[string]bool{"container": true},
		MatchAny:      true,
		ExecUserAllow: map[string]bool{"1000": true, "1001": true, "deploy": true},
	}}

	containers := map[string]map[string]interface{}{
		"any": {
			"Id":   "anyfull",
			"Name": "/any-container",
			"Config": map[string]interface{}{
				"Image":  "myapp",
				"Labels": map[string]interface{}{},
			},
		},
	}
	server := mockDockerServer(containers)
	defer server.Close()

	cfg := &config.Config{Rules: rules, Default: "deny", Upstream: server.URL}
	e := newTestEngineWithHTTP(cfg, server.URL)

	class := classifier.Classification{Action: "exec", Target: "container", ID: "any"}
	req := httptest.NewRequest("POST", "/containers/any/exec", nil)

	// Allowed users
	for _, user := range []string{"1000", "1001", "deploy"} {
		body := []byte(fmt.Sprintf(`{"User": "%s", "Cmd": ["sh"]}`, user))
		decision := e.Authorize(req, class, body)
		if !decision.Allowed {
			t.Errorf("expected allow for user %s, got: %s", user, decision.Reason)
		}
	}

	// Denied users
	for _, user := range []string{"0", "root", "9999", ""} {
		body := []byte(fmt.Sprintf(`{"User": "%s", "Cmd": ["sh"]}`, user))
		decision := e.Authorize(req, class, body)
		if decision.Allowed {
			t.Errorf("expected deny for user %s", user)
		}
	}
}

func TestEngine_ExecNoUserConfig_Denied(t *testing.T) {
	// Rule has exec action but no ExecUser/ExecUserAllow → deny
	rules := []*config.Rule{{
		Name:     "nouser",
		Actions:  map[string]bool{"exec": true},
		Targets:  map[string]bool{"container": true},
		MatchAny: true,
	}}

	containers := map[string]map[string]interface{}{
		"any": {
			"Id":   "anyfull",
			"Name": "/any-container",
			"Config": map[string]interface{}{
				"Image":  "myapp",
				"Labels": map[string]interface{}{},
			},
		},
	}
	server := mockDockerServer(containers)
	defer server.Close()

	cfg := &config.Config{Rules: rules, Default: "deny", Upstream: server.URL}
	e := newTestEngineWithHTTP(cfg, server.URL)

	body := []byte(`{"User": "1000", "Cmd": ["sh"]}`)
	class := classifier.Classification{Action: "exec", Target: "container", ID: "any"}
	req := httptest.NewRequest("POST", "/containers/any/exec", nil)
	decision := e.Authorize(req, class, body)
	if decision.Allowed {
		t.Error("expected deny when no exec user config is set")
	}
}

func TestEngine_ExecStartFollowup(t *testing.T) {
	rules := []*config.Rule{{
		Name:          "devexec",
		Actions:       map[string]bool{"exec": true},
		Targets:       map[string]bool{"container": true},
		MatchAny:      true,
		ExecUserAllow: map[string]bool{"1000": true},
	}}

	containers := map[string]map[string]interface{}{
		"mycontainer": {
			"Id":   "mycontainerfull",
			"Name": "/mycontainer",
			"Config": map[string]interface{}{
				"Image":  "myapp",
				"Labels": map[string]interface{}{},
			},
		},
	}
	server := mockDockerServer(containers)
	defer server.Close()

	cfg := &config.Config{Rules: rules, Default: "deny", Upstream: server.URL}
	e := newTestEngineWithHTTP(cfg, server.URL)

	// Store exec mapping (simulates what happens after exec create)
	e.StoreExecID("exec123", "mycontainer")

	// exec.start with known exec ID should be allowed
	class := classifier.Classification{Action: "exec.start", Target: "container", ID: "exec123"}
	req := httptest.NewRequest("POST", "/exec/exec123/start", nil)
	decision := e.Authorize(req, class, nil)
	if !decision.Allowed {
		t.Errorf("expected allow for known exec start, got: %s", decision.Reason)
	}

	// exec.start with unknown exec ID should be denied
	class = classifier.Classification{Action: "exec.start", Target: "container", ID: "unknown456"}
	req = httptest.NewRequest("POST", "/exec/unknown456/start", nil)
	decision = e.Authorize(req, class, nil)
	if decision.Allowed {
		t.Error("expected deny for unknown exec ID")
	}
}

func TestEngine_CreateAction_ImageMatch(t *testing.T) {
	rules := []*config.Rule{{
		Name:       "acmecreate",
		Actions:    map[string]bool{"create": true},
		Targets:    map[string]bool{"container": true},
		MatchImage: "registry.acme.io/*",
	}}

	cfg := &config.Config{Rules: rules, Default: "deny", Upstream: "unix:///var/run/docker.sock"}
	e := NewEngine(cfg)

	// Allowed image
	body := []byte(`{"Image": "registry.acme.io/myapp:latest", "Cmd": ["./run"]}`)
	class := classifier.Classification{Action: "create", Target: "container"}
	req := httptest.NewRequest("POST", "/containers/create", nil)
	decision := e.Authorize(req, class, body)
	if !decision.Allowed {
		t.Errorf("expected allow for acme image create, got: %s", decision.Reason)
	}

	// Denied image
	body = []byte(`{"Image": "docker.io/library/nginx:latest", "Cmd": ["nginx"]}`)
	decision = e.Authorize(req, class, body)
	if decision.Allowed {
		t.Error("expected deny for non-acme image create")
	}
}

func TestEngine_CreateAction_LabelMatch(t *testing.T) {
	rules := []*config.Rule{{
		Name:        "labeled",
		Actions:     map[string]bool{"create": true},
		Targets:     map[string]bool{"container": true},
		MatchLabels: map[string]string{"managed": "true"},
	}}

	cfg := &config.Config{Rules: rules, Default: "deny", Upstream: "unix:///var/run/docker.sock"}
	e := NewEngine(cfg)

	// Allowed with label
	body := []byte(`{"Image": "myapp", "Labels": {"managed": "true"}}`)
	class := classifier.Classification{Action: "create", Target: "container"}
	req := httptest.NewRequest("POST", "/containers/create", nil)
	decision := e.Authorize(req, class, body)
	if !decision.Allowed {
		t.Errorf("expected allow for labeled create, got: %s", decision.Reason)
	}

	// Denied without label
	body = []byte(`{"Image": "myapp", "Labels": {"other": "value"}}`)
	decision = e.Authorize(req, class, body)
	if decision.Allowed {
		t.Error("expected deny for create without required label")
	}

	// Denied with no labels
	body = []byte(`{"Image": "myapp"}`)
	decision = e.Authorize(req, class, body)
	if decision.Allowed {
		t.Error("expected deny for create with no labels at all")
	}
}

func TestEngine_MultipleRulesORed(t *testing.T) {
	rules := []*config.Rule{
		{
			Name:        "devstart",
			Actions:     map[string]bool{"start": true},
			Targets:     map[string]bool{"container": true},
			MatchLabels: map[string]string{"team": "dev"},
		},
		{
			Name:        "prodstart",
			Actions:     map[string]bool{"start": true},
			Targets:     map[string]bool{"container": true},
			MatchLabels: map[string]string{"team": "prod"},
		},
	}

	containers := map[string]map[string]interface{}{
		"dev1": {
			"Id": "dev1full", "Name": "/dev-app",
			"Config": map[string]interface{}{"Image": "app", "Labels": map[string]interface{}{"team": "dev"}},
		},
		"prod1": {
			"Id": "prod1full", "Name": "/prod-app",
			"Config": map[string]interface{}{"Image": "app", "Labels": map[string]interface{}{"team": "prod"}},
		},
		"other": {
			"Id": "otherfull", "Name": "/other-app",
			"Config": map[string]interface{}{"Image": "app", "Labels": map[string]interface{}{"team": "staging"}},
		},
	}
	server := mockDockerServer(containers)
	defer server.Close()

	cfg := &config.Config{Rules: rules, Default: "deny", Upstream: server.URL}
	e := newTestEngineWithHTTP(cfg, server.URL)

	// Dev matches first rule
	class := classifier.Classification{Action: "start", Target: "container", ID: "dev1"}
	req := httptest.NewRequest("POST", "/containers/dev1/start", nil)
	decision := e.Authorize(req, class, nil)
	if !decision.Allowed {
		t.Errorf("dev1 should be allowed: %s", decision.Reason)
	}

	// Prod matches second rule
	class = classifier.Classification{Action: "start", Target: "container", ID: "prod1"}
	req = httptest.NewRequest("POST", "/containers/prod1/start", nil)
	decision = e.Authorize(req, class, nil)
	if !decision.Allowed {
		t.Errorf("prod1 should be allowed: %s", decision.Reason)
	}

	// Staging matches neither
	class = classifier.Classification{Action: "start", Target: "container", ID: "other"}
	req = httptest.NewRequest("POST", "/containers/other/start", nil)
	decision = e.Authorize(req, class, nil)
	if decision.Allowed {
		t.Error("staging should be denied")
	}
}

func TestEngine_ActionMismatch_Denied(t *testing.T) {
	rules := []*config.Rule{{
		Name:     "readonly",
		Actions:  map[string]bool{"list": true, "inspect": true},
		Targets:  map[string]bool{"container": true},
		MatchAny: true,
	}}

	containers := map[string]map[string]interface{}{
		"c1": {
			"Id": "c1full", "Name": "/c1",
			"Config": map[string]interface{}{"Image": "app", "Labels": map[string]interface{}{}},
		},
	}
	server := mockDockerServer(containers)
	defer server.Close()

	cfg := &config.Config{Rules: rules, Default: "deny", Upstream: server.URL}
	e := newTestEngineWithHTTP(cfg, server.URL)

	// Stop is not in the rule's actions
	class := classifier.Classification{Action: "stop", Target: "container", ID: "c1"}
	req := httptest.NewRequest("POST", "/containers/c1/stop", nil)
	decision := e.Authorize(req, class, nil)
	if decision.Allowed {
		t.Error("expected deny for action not in rule")
	}
}

func TestEngine_TargetMismatch_Denied(t *testing.T) {
	rules := []*config.Rule{{
		Name:     "containeronly",
		Actions:  map[string]bool{"list": true},
		Targets:  map[string]bool{"container": true},
		MatchAny: true,
	}}

	cfg := &config.Config{Rules: rules, Default: "deny", Upstream: "unix:///var/run/docker.sock"}
	e := NewEngine(cfg)

	// Image target not covered by rule
	class := classifier.Classification{Action: "list", Target: "image"}
	req := httptest.NewRequest("GET", "/images/json", nil)
	decision := e.Authorize(req, class, nil)
	if decision.Allowed {
		t.Error("expected deny for target not in rule")
	}
}

func TestEngine_MultipleSelectorsANDed(t *testing.T) {
	rules := []*config.Rule{{
		Name:        "strict",
		Actions:     map[string]bool{"restart": true},
		Targets:     map[string]bool{"container": true},
		MatchLabels: map[string]string{"team": "dev", "env": "staging"},
		MatchName:   "worker-*",
	}}

	containers := map[string]map[string]interface{}{
		"allMatch": {
			"Id": "allMatchFull", "Name": "/worker-01",
			"Config": map[string]interface{}{
				"Image":  "app",
				"Labels": map[string]interface{}{"team": "dev", "env": "staging"},
			},
		},
		"labelMismatch": {
			"Id": "labelMismatchFull", "Name": "/worker-02",
			"Config": map[string]interface{}{
				"Image":  "app",
				"Labels": map[string]interface{}{"team": "dev", "env": "prod"},
			},
		},
		"nameMismatch": {
			"Id": "nameMismatchFull", "Name": "/api-01",
			"Config": map[string]interface{}{
				"Image":  "app",
				"Labels": map[string]interface{}{"team": "dev", "env": "staging"},
			},
		},
	}
	server := mockDockerServer(containers)
	defer server.Close()

	cfg := &config.Config{Rules: rules, Default: "deny", Upstream: server.URL}
	e := newTestEngineWithHTTP(cfg, server.URL)

	// All match
	class := classifier.Classification{Action: "restart", Target: "container", ID: "allMatch"}
	req := httptest.NewRequest("POST", "/containers/allMatch/restart", nil)
	decision := e.Authorize(req, class, nil)
	if !decision.Allowed {
		t.Errorf("expected allow when all selectors match, got: %s", decision.Reason)
	}

	// Label mismatch
	class = classifier.Classification{Action: "restart", Target: "container", ID: "labelMismatch"}
	req = httptest.NewRequest("POST", "/containers/labelMismatch/restart", nil)
	decision = e.Authorize(req, class, nil)
	if decision.Allowed {
		t.Error("expected deny when label doesn't match")
	}

	// Name mismatch
	class = classifier.Classification{Action: "restart", Target: "container", ID: "nameMismatch"}
	req = httptest.NewRequest("POST", "/containers/nameMismatch/restart", nil)
	decision = e.Authorize(req, class, nil)
	if decision.Allowed {
		t.Error("expected deny when name doesn't match")
	}
}

func TestGlobMatch(t *testing.T) {
	tests := []struct {
		pattern string
		value   string
		want    bool
	}{
		{"*", "anything", true},
		{"dev-*", "dev-app", true},
		{"dev-*", "prod-app", false},
		{"*.acme.io", "registry.acme.io", true},
		{"worker-??", "worker-01", true},
		{"worker-??", "worker-001", false},
		{"exact", "exact", true},
		{"exact", "other", false},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s/%s", tt.pattern, tt.value), func(t *testing.T) {
			got := globMatch(tt.pattern, tt.value)
			if got != tt.want {
				t.Errorf("globMatch(%q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
			}
		})
	}
}

// newTestEngineWithHTTP creates an engine that uses HTTP instead of unix socket for testing.
func newTestEngineWithHTTP(cfg *config.Config, serverURL string) *Engine {
	e := NewEngine(cfg)
	// Override the upstream to use HTTP test server
	e.upstream = serverURL
	// We need to override the inspect function to use HTTP
	// Since Engine.inspectContainer uses upstreamClient which dials unix,
	// we need a different approach for testing.
	// Let's override the metaCache with pre-populated data instead.

	// Actually, let's patch the Engine to handle http:// upstream too
	return e
}
