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

func TestEngine_DefaultAllow_AllowsUnmatchedNonExec(t *testing.T) {
	cfg := &config.Config{Rules: nil, Default: "allow", Upstream: "unix:///var/run/docker.sock"}
	e := NewEngine(cfg)

	class := classifier.Classification{Action: "list", Target: "container"}
	req := httptest.NewRequest("GET", "/containers/json", nil)
	decision := e.Authorize(req, class, nil)
	if !decision.Allowed {
		t.Errorf("expected default allow for non-exec, got: %s", decision.Reason)
	}
}

func TestEngine_DefaultAsk_AsksForUnmatchedNonExec(t *testing.T) {
	cfg := &config.Config{Rules: nil, Default: "ask", Upstream: "unix:///var/run/docker.sock"}
	e := NewEngine(cfg)

	class := classifier.Classification{Action: "list", Target: "container"}
	req := httptest.NewRequest("GET", "/containers/json", nil)
	decision := e.Authorize(req, class, nil)
	if !decision.NeedsConfirmation {
		t.Fatalf("expected default ask to require confirmation, got: %+v", decision)
	}
	if decision.RuleName != "default" {
		t.Fatalf("expected default rule name, got %s", decision.RuleName)
	}
}

func TestEngine_DefaultAllow_DoesNotAllowUnknownOrExec(t *testing.T) {
	tests := []classifier.Classification{
		{Action: "unknown", Target: "unknown"},
		{Action: "exec", Target: "container", ID: "abc123"},
	}

	for _, defaultPolicy := range []string{"allow", "ask"} {
		t.Run(defaultPolicy, func(t *testing.T) {
			cfg := &config.Config{Rules: nil, Default: defaultPolicy, Upstream: "unix:///var/run/docker.sock"}
			e := NewEngine(cfg)

			for _, class := range tests {
				req := httptest.NewRequest("POST", "/", nil)
				decision := e.Authorize(req, class, []byte(`{"User":"1000"}`))
				if decision.Allowed || decision.NeedsConfirmation {
					t.Errorf("expected deny for %+v with default %s, got %+v", class, defaultPolicy, decision)
				}
			}
		})
	}
}

func TestEngine_AskExecRuleAsksForCreateAndFollowup(t *testing.T) {
	rules := []*config.Rule{{
		Name:          "askexec",
		Decision:      config.DecisionAsk,
		Actions:       map[string]bool{"exec": true},
		Targets:       map[string]bool{"container": true},
		MatchAny:      true,
		ExecUserAllow: map[string]bool{"1000": true},
	}}

	containers := map[string]map[string]interface{}{
		"app": {
			"Id":   "appfull",
			"Name": "/app",
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

	createClass := classifier.Classification{Action: "exec", Target: "container", ID: "app"}
	createReq := httptest.NewRequest("POST", "/containers/app/exec", nil)
	createDecision := e.Authorize(createReq, createClass, []byte(`{"User":"1000","Cmd":["sh"]}`))
	if !createDecision.NeedsConfirmation {
		t.Fatalf("expected exec create to require confirmation, got: %+v", createDecision)
	}

	e.StoreExecID("exec123", "app")
	followupClass := classifier.Classification{Action: "exec.start", Target: "container", ID: "exec123"}
	followupReq := httptest.NewRequest("POST", "/exec/exec123/start", nil)
	followupDecision := e.Authorize(followupReq, followupClass, nil)
	if !followupDecision.NeedsConfirmation {
		t.Fatalf("expected exec followup to require confirmation, got: %+v", followupDecision)
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

func TestEngine_MatchAny_NonContainerIDDoesNotInspectContainer(t *testing.T) {
	rules := []*config.Rule{{
		Name:     "images",
		Actions:  map[string]bool{"inspect": true},
		Targets:  map[string]bool{"image": true},
		MatchAny: true,
	}}

	server := mockDockerServer(nil)
	defer server.Close()

	cfg := &config.Config{Rules: rules, Default: "deny", Upstream: server.URL}
	e := newTestEngineWithHTTP(cfg, server.URL)

	class := classifier.Classification{Action: "inspect", Target: "image", ID: "nginx"}
	req := httptest.NewRequest("GET", "/images/nginx/json", nil)
	decision := e.Authorize(req, class, nil)
	if !decision.Allowed {
		t.Errorf("expected MatchAny image inspect to allow without container inspect, got: %s", decision.Reason)
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
				"User":   "1000",
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

	// Empty user inherits the container's configured default user.
	body = []byte(`{"Cmd": ["sh"]}`)
	decision = e.Authorize(req, class, body)
	if !decision.Allowed {
		t.Errorf("expected allow for inherited exec user, got: %s", decision.Reason)
	}

	// Exact user requires full string match, not just the user component
	body = []byte(`{"User": "1000:1000", "Cmd": ["sh"]}`)
	decision = e.Authorize(req, class, body)
	if decision.Allowed {
		t.Error("expected deny when exact exec user does not match full user:group string")
	}

	// Empty string user also inherits the container's configured default user.
	body = []byte(`{"User": "", "Cmd": ["sh"]}`)
	decision = e.Authorize(req, class, body)
	if !decision.Allowed {
		t.Errorf("expected allow for empty string inherited exec user, got: %s", decision.Reason)
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

func TestEngine_ExecUserInheritsConfiguredDefaultUser(t *testing.T) {
	rules := []*config.Rule{{
		Name:          "devexec",
		Actions:       map[string]bool{"exec": true},
		Targets:       map[string]bool{"container": true},
		MatchAny:      true,
		ExecUserAllow: map[string]bool{"1000": true, "node": true},
	}}

	containers := map[string]map[string]interface{}{
		"numeric": {
			"Id":   "numericfull",
			"Name": "/numeric-container",
			"Config": map[string]interface{}{
				"Image":  "node",
				"Labels": map[string]interface{}{},
				"User":   "1000:1000",
			},
		},
		"named": {
			"Id":   "namedfull",
			"Name": "/named-container",
			"Config": map[string]interface{}{
				"Image":  "node",
				"Labels": map[string]interface{}{},
				"User":   "node",
			},
		},
	}
	server := mockDockerServer(containers)
	defer server.Close()

	cfg := &config.Config{Rules: rules, Default: "deny", Upstream: server.URL}
	e := newTestEngineWithHTTP(cfg, server.URL)

	for _, id := range []string{"numeric", "named"} {
		t.Run(id, func(t *testing.T) {
			class := classifier.Classification{Action: "exec", Target: "container", ID: id}
			req := httptest.NewRequest("POST", "/containers/"+id+"/exec", nil)
			decision := e.Authorize(req, class, []byte(`{"Cmd":["sh"]}`))
			if !decision.Allowed {
				t.Errorf("expected allow for inherited default user on %s, got: %s", id, decision.Reason)
			}
		})
	}
}

func TestEngine_ExecUserDoesNotInheritEmptyOrRootDefaultUser(t *testing.T) {
	rules := []*config.Rule{{
		Name:          "devexec",
		Actions:       map[string]bool{"exec": true},
		Targets:       map[string]bool{"container": true},
		MatchAny:      true,
		ExecUserAllow: map[string]bool{"root": true, "0": true, "1000": true},
	}}

	containers := map[string]map[string]interface{}{
		"empty": {
			"Id":   "emptyfull",
			"Name": "/empty-container",
			"Config": map[string]interface{}{
				"Image":  "myapp",
				"Labels": map[string]interface{}{},
			},
		},
		"root": {
			"Id":   "rootfull",
			"Name": "/root-container",
			"Config": map[string]interface{}{
				"Image":  "myapp",
				"Labels": map[string]interface{}{},
				"User":   "root",
			},
		},
		"uid0": {
			"Id":   "uid0full",
			"Name": "/uid0-container",
			"Config": map[string]interface{}{
				"Image":  "myapp",
				"Labels": map[string]interface{}{},
				"User":   "1000:0",
			},
		},
	}
	server := mockDockerServer(containers)
	defer server.Close()

	cfg := &config.Config{Rules: rules, Default: "deny", Upstream: server.URL}
	e := newTestEngineWithHTTP(cfg, server.URL)

	for _, id := range []string{"empty", "root", "uid0"} {
		t.Run(id, func(t *testing.T) {
			class := classifier.Classification{Action: "exec", Target: "container", ID: id}
			req := httptest.NewRequest("POST", "/containers/"+id+"/exec", nil)
			decision := e.Authorize(req, class, []byte(`{"Cmd":["sh"]}`))
			if decision.Allowed {
				t.Errorf("expected deny for inherited unsafe default user on %s", id)
			}
		})
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

func TestEngine_ExecRootAlwaysBlocked(t *testing.T) {
	// Even if ExecUserAllow includes "root" or "0", they should be blocked
	rules := []*config.Rule{{
		Name:          "roottest",
		Actions:       map[string]bool{"exec": true},
		Targets:       map[string]bool{"container": true},
		MatchAny:      true,
		ExecUserAllow: map[string]bool{"root": true, "0": true, "1000": true},
	}}

	containers := map[string]map[string]interface{}{
		"any": {
			"Id": "anyfull", "Name": "/any-container",
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

	// root always blocked
	body := []byte(`{"User": "root", "Cmd": ["sh"]}`)
	decision := e.Authorize(req, class, body)
	if decision.Allowed {
		t.Error("expected deny for root even if in allowlist")
	}

	// UID 0 always blocked
	body = []byte(`{"User": "0", "Cmd": ["sh"]}`)
	decision = e.Authorize(req, class, body)
	if decision.Allowed {
		t.Error("expected deny for UID 0 even if in allowlist")
	}

	// root:root format blocked
	body = []byte(`{"User": "root:root", "Cmd": ["sh"]}`)
	decision = e.Authorize(req, class, body)
	if decision.Allowed {
		t.Error("expected deny for root:root")
	}

	// non-root user with root group blocked
	body = []byte(`{"User": "1000:0", "Cmd": ["sh"]}`)
	decision = e.Authorize(req, class, body)
	if decision.Allowed {
		t.Error("expected deny for 1000:0")
	}

	body = []byte(`{"User": "1000:root", "Cmd": ["sh"]}`)
	decision = e.Authorize(req, class, body)
	if decision.Allowed {
		t.Error("expected deny for 1000:root")
	}

	// 0:0 format blocked
	body = []byte(`{"User": "0:0", "Cmd": ["sh"]}`)
	decision = e.Authorize(req, class, body)
	if decision.Allowed {
		t.Error("expected deny for 0:0")
	}

	// user:group with allowed user works (group ignored)
	body = []byte(`{"User": "1000:1000", "Cmd": ["sh"]}`)
	decision = e.Authorize(req, class, body)
	if !decision.Allowed {
		t.Errorf("expected allow for 1000:1000, got: %s", decision.Reason)
	}

	// allowed user still works
	body = []byte(`{"User": "1000", "Cmd": ["sh"]}`)
	decision = e.Authorize(req, class, body)
	if !decision.Allowed {
		t.Errorf("expected allow for 1000, got: %s", decision.Reason)
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

func TestEngine_RuleDecisionAskRequiresConfirmation(t *testing.T) {
	rules := []*config.Rule{{
		Name:     "confirmrestart",
		Decision: config.DecisionAsk,
		Actions:  map[string]bool{"restart": true},
		Targets:  map[string]bool{"container": true},
		MatchAny: true,
	}}

	cfg := &config.Config{Rules: rules, Default: "deny", Upstream: "unix:///var/run/docker.sock"}
	e := NewEngine(cfg)

	class := classifier.Classification{Action: "restart", Target: "container", ID: "app"}
	req := httptest.NewRequest("POST", "/containers/app/restart", nil)
	decision := e.Authorize(req, class, nil)
	if !decision.NeedsConfirmation {
		t.Fatalf("expected confirmation decision, got allowed=%v reason=%s", decision.Allowed, decision.Reason)
	}
	if decision.Allowed {
		t.Fatal("ask decision should not be allowed until the proxy confirms it")
	}
	if decision.RuleName != "confirmrestart" {
		t.Fatalf("expected rule name confirmrestart, got %s", decision.RuleName)
	}
}

func TestEngine_RuleDecisionDenyOverridesAllow(t *testing.T) {
	rules := []*config.Rule{
		{
			Name:     "allowrestart",
			Decision: config.DecisionAllow,
			Actions:  map[string]bool{"restart": true},
			Targets:  map[string]bool{"container": true},
			MatchAny: true,
		},
		{
			Name:     "denyrestart",
			Decision: config.DecisionDeny,
			Actions:  map[string]bool{"restart": true},
			Targets:  map[string]bool{"container": true},
			MatchAny: true,
		},
	}

	cfg := &config.Config{Rules: rules, Default: "deny", Upstream: "unix:///var/run/docker.sock"}
	e := NewEngine(cfg)

	class := classifier.Classification{Action: "restart", Target: "container", ID: "app"}
	req := httptest.NewRequest("POST", "/containers/app/restart", nil)
	decision := e.Authorize(req, class, nil)
	if decision.Allowed || decision.NeedsConfirmation {
		t.Fatalf("expected deny to override allow, got allowed=%v confirm=%v", decision.Allowed, decision.NeedsConfirmation)
	}
	if decision.RuleName != "denyrestart" {
		t.Fatalf("expected denyrestart to decide, got %s", decision.RuleName)
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

func TestEngine_ContainerLabelRuleScopedToLabeledContainer(t *testing.T) {
	containers := map[string]map[string]interface{}{
		"labeled": {
			"Id":   "labeledfull",
			"Name": "/labeled-app",
			"Config": map[string]interface{}{
				"Image": "myapp",
				"Labels": map[string]interface{}{
					"dpp.rule.self.action": "restart",
					"dpp.rule.self.match":  "*",
				},
			},
		},
		"other": {
			"Id":   "otherfull",
			"Name": "/other-app",
			"Config": map[string]interface{}{
				"Image":  "myapp",
				"Labels": map[string]interface{}{},
			},
		},
	}
	server := mockDockerServer(containers)
	defer server.Close()

	cfg := &config.Config{Default: "deny", Upstream: server.URL}
	e := newTestEngineWithHTTP(cfg, server.URL)

	class := classifier.Classification{Action: "restart", Target: "container", ID: "labeled"}
	req := httptest.NewRequest("POST", "/containers/labeled/restart", nil)
	decision := e.Authorize(req, class, nil)
	if !decision.Allowed {
		t.Errorf("expected labeled container rule to allow restart, got: %s", decision.Reason)
	}

	class = classifier.Classification{Action: "restart", Target: "container", ID: "other"}
	req = httptest.NewRequest("POST", "/containers/other/restart", nil)
	decision = e.Authorize(req, class, nil)
	if decision.Allowed {
		t.Error("expected container label rule to apply only to the labeled container")
	}
}

func TestEngine_ContainerLabelRuleRequiresExecUser(t *testing.T) {
	containers := map[string]map[string]interface{}{
		"shell": {
			"Id":   "shellfull",
			"Name": "/shell-app",
			"Config": map[string]interface{}{
				"Image": "myapp",
				"Labels": map[string]interface{}{
					"dpp.rule.shell.action":          "exec",
					"dpp.rule.shell.match":           "*",
					"dpp.rule.shell.exec-user-allow": "1000,deploy",
				},
				"User": "1000:1000",
			},
		},
	}
	server := mockDockerServer(containers)
	defer server.Close()

	cfg := &config.Config{Default: "deny", Upstream: server.URL}
	e := newTestEngineWithHTTP(cfg, server.URL)

	class := classifier.Classification{Action: "exec", Target: "container", ID: "shell"}
	req := httptest.NewRequest("POST", "/containers/shell/exec", nil)

	decision := e.Authorize(req, class, []byte(`{"User":"1000","Cmd":["sh"]}`))
	if !decision.Allowed {
		t.Errorf("expected label-defined exec rule to allow user 1000, got: %s", decision.Reason)
	}

	decision = e.Authorize(req, class, []byte(`{"User":"root","Cmd":["sh"]}`))
	if decision.Allowed {
		t.Error("expected label-defined exec rule to keep blocking root")
	}

	decision = e.Authorize(req, class, []byte(`{"Cmd":["sh"]}`))
	if !decision.Allowed {
		t.Errorf("expected label-defined exec rule to allow inherited default user, got: %s", decision.Reason)
	}
}

func TestEngine_InvalidContainerLabelRuleDoesNotBlockEnvRule(t *testing.T) {
	rules := []*config.Rule{{
		Name:        "devrestart",
		Actions:     map[string]bool{"restart": true},
		Targets:     map[string]bool{"container": true},
		MatchLabels: map[string]string{"team": "dev"},
	}}

	containers := map[string]map[string]interface{}{
		"app": {
			"Id":   "appfull",
			"Name": "/dev-app",
			"Config": map[string]interface{}{
				"Image": "myapp",
				"Labels": map[string]interface{}{
					"team":                "dev",
					"dpp.rule.bad.action": "restart",
					"dpp.rule.bad.acton":  "stop",
				},
			},
		},
	}
	server := mockDockerServer(containers)
	defer server.Close()

	cfg := &config.Config{Rules: rules, Default: "deny", Upstream: server.URL}
	e := newTestEngineWithHTTP(cfg, server.URL)

	class := classifier.Classification{Action: "restart", Target: "container", ID: "app"}
	req := httptest.NewRequest("POST", "/containers/app/restart", nil)
	decision := e.Authorize(req, class, nil)
	if !decision.Allowed {
		t.Errorf("expected env rule to allow despite invalid label rule, got: %s", decision.Reason)
	}
}

func TestEngine_ContainerLabelRuleSelectorsAreANDed(t *testing.T) {
	ruleLabels := map[string]interface{}{
		"dpp.rule.strict.action":          "restart",
		"dpp.rule.strict.match-name":      "web-*",
		"dpp.rule.strict.match-image":     "registry.acme.io/*",
		"dpp.rule.strict.match-id":        "abc123",
		"dpp.rule.strict.match-label.env": "prod",
	}

	containers := map[string]map[string]interface{}{
		"match": {
			"Id":   "abc123match",
			"Name": "/web-01",
			"Config": map[string]interface{}{
				"Image":  "registry.acme.io/web:latest",
				"Labels": mergeLabels(ruleLabels, map[string]interface{}{"env": "prod"}),
			},
		},
		"badname": {
			"Id":   "abc123badname",
			"Name": "/api-01",
			"Config": map[string]interface{}{
				"Image":  "registry.acme.io/web:latest",
				"Labels": mergeLabels(ruleLabels, map[string]interface{}{"env": "prod"}),
			},
		},
		"badimage": {
			"Id":   "abc123badimage",
			"Name": "/web-02",
			"Config": map[string]interface{}{
				"Image":  "docker.io/library/nginx:latest",
				"Labels": mergeLabels(ruleLabels, map[string]interface{}{"env": "prod"}),
			},
		},
		"badid": {
			"Id":   "def456badid",
			"Name": "/web-03",
			"Config": map[string]interface{}{
				"Image":  "registry.acme.io/web:latest",
				"Labels": mergeLabels(ruleLabels, map[string]interface{}{"env": "prod"}),
			},
		},
		"badlabel": {
			"Id":   "abc123badlabel",
			"Name": "/web-04",
			"Config": map[string]interface{}{
				"Image":  "registry.acme.io/web:latest",
				"Labels": mergeLabels(ruleLabels, map[string]interface{}{"env": "staging"}),
			},
		},
	}
	server := mockDockerServer(containers)
	defer server.Close()

	cfg := &config.Config{Default: "deny", Upstream: server.URL}
	e := newTestEngineWithHTTP(cfg, server.URL)

	tests := []struct {
		id      string
		allowed bool
	}{
		{id: "match", allowed: true},
		{id: "badname", allowed: false},
		{id: "badimage", allowed: false},
		{id: "badid", allowed: false},
		{id: "badlabel", allowed: false},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			class := classifier.Classification{Action: "restart", Target: "container", ID: tt.id}
			req := httptest.NewRequest("POST", "/containers/"+tt.id+"/restart", nil)
			decision := e.Authorize(req, class, nil)
			if decision.Allowed != tt.allowed {
				t.Fatalf("allowed = %v, want %v; reason: %s", decision.Allowed, tt.allowed, decision.Reason)
			}
		})
	}
}

func TestEngine_ContainerLabelRuleActionMismatchDenied(t *testing.T) {
	containers := map[string]map[string]interface{}{
		"app": {
			"Id":   "appfull",
			"Name": "/app",
			"Config": map[string]interface{}{
				"Image": "myapp",
				"Labels": map[string]interface{}{
					"dpp.rule.self.action": "stop",
					"dpp.rule.self.match":  "*",
				},
			},
		},
	}
	server := mockDockerServer(containers)
	defer server.Close()

	cfg := &config.Config{Default: "deny", Upstream: server.URL}
	e := newTestEngineWithHTTP(cfg, server.URL)

	class := classifier.Classification{Action: "restart", Target: "container", ID: "app"}
	req := httptest.NewRequest("POST", "/containers/app/restart", nil)
	decision := e.Authorize(req, class, nil)
	if decision.Allowed {
		t.Error("expected deny when label rule action does not match request action")
	}
}

func TestEngine_ContainerLabelRuleTargetMismatchDenied(t *testing.T) {
	containers := map[string]map[string]interface{}{
		"app": {
			"Id":   "appfull",
			"Name": "/app",
			"Config": map[string]interface{}{
				"Image": "myapp",
				"Labels": map[string]interface{}{
					"dpp.rule.self.action": "restart",
					"dpp.rule.self.target": "image",
					"dpp.rule.self.match":  "*",
				},
			},
		},
	}
	server := mockDockerServer(containers)
	defer server.Close()

	cfg := &config.Config{Default: "deny", Upstream: server.URL}
	e := newTestEngineWithHTTP(cfg, server.URL)

	class := classifier.Classification{Action: "restart", Target: "container", ID: "app"}
	req := httptest.NewRequest("POST", "/containers/app/restart", nil)
	decision := e.Authorize(req, class, nil)
	if decision.Allowed {
		t.Error("expected deny when label rule target does not match request target")
	}
}

func TestEngine_ContainerLabelRuleCanAllowWhenStaticRuleMisses(t *testing.T) {
	rules := []*config.Rule{{
		Name:        "prodrestart",
		Actions:     map[string]bool{"restart": true},
		Targets:     map[string]bool{"container": true},
		MatchLabels: map[string]string{"team": "prod"},
	}}

	containers := map[string]map[string]interface{}{
		"app": {
			"Id":   "appfull",
			"Name": "/dev-app",
			"Config": map[string]interface{}{
				"Image": "myapp",
				"Labels": map[string]interface{}{
					"team":                 "dev",
					"dpp.rule.self.action": "restart",
					"dpp.rule.self.match":  "*",
				},
			},
		},
	}
	server := mockDockerServer(containers)
	defer server.Close()

	cfg := &config.Config{Rules: rules, Default: "deny", Upstream: server.URL}
	e := newTestEngineWithHTTP(cfg, server.URL)

	class := classifier.Classification{Action: "restart", Target: "container", ID: "app"}
	req := httptest.NewRequest("POST", "/containers/app/restart", nil)
	decision := e.Authorize(req, class, nil)
	if !decision.Allowed {
		t.Errorf("expected label rule to allow after static rule misses, got: %s", decision.Reason)
	}
}

func TestEngine_ContainerLabelRuleWithNoActionDoesNotAuthorize(t *testing.T) {
	containers := map[string]map[string]interface{}{
		"app": {
			"Id":   "appfull",
			"Name": "/app",
			"Config": map[string]interface{}{
				"Image": "myapp",
				"Labels": map[string]interface{}{
					"dpp.rule.noop.match": "*",
				},
			},
		},
	}
	server := mockDockerServer(containers)
	defer server.Close()

	cfg := &config.Config{Default: "deny", Upstream: server.URL}
	e := newTestEngineWithHTTP(cfg, server.URL)

	class := classifier.Classification{Action: "restart", Target: "container", ID: "app"}
	req := httptest.NewRequest("POST", "/containers/app/restart", nil)
	decision := e.Authorize(req, class, nil)
	if decision.Allowed {
		t.Error("expected label rule without action to be ignored")
	}
}

func TestEngine_InvalidContainerLabelRuleDeniesWhenNoRuleAllows(t *testing.T) {
	containers := map[string]map[string]interface{}{
		"app": {
			"Id":   "appfull",
			"Name": "/app",
			"Config": map[string]interface{}{
				"Image": "myapp",
				"Labels": map[string]interface{}{
					"dpp.rule.bad.action": "restart",
					"dpp.rule.bad.acton":  "stop",
				},
			},
		},
	}
	server := mockDockerServer(containers)
	defer server.Close()

	cfg := &config.Config{Default: "deny", Upstream: server.URL}
	e := newTestEngineWithHTTP(cfg, server.URL)

	class := classifier.Classification{Action: "restart", Target: "container", ID: "app"}
	req := httptest.NewRequest("POST", "/containers/app/restart", nil)
	decision := e.Authorize(req, class, nil)
	if decision.Allowed {
		t.Fatal("expected invalid label rule to deny when no rule allows")
	}
	if !strings.Contains(decision.Reason, "invalid container label rule") {
		t.Fatalf("expected invalid label rule reason, got: %s", decision.Reason)
	}
}

func TestEngine_InvalidContainerLabelRuleDeniesAfterStaticRulesMiss(t *testing.T) {
	rules := []*config.Rule{{
		Name:        "prodrestart",
		Actions:     map[string]bool{"restart": true},
		Targets:     map[string]bool{"container": true},
		MatchLabels: map[string]string{"team": "prod"},
	}}

	containers := map[string]map[string]interface{}{
		"app": {
			"Id":   "appfull",
			"Name": "/dev-app",
			"Config": map[string]interface{}{
				"Image": "myapp",
				"Labels": map[string]interface{}{
					"team":                "dev",
					"dpp.rule.bad.action": "restart",
					"dpp.rule.bad.acton":  "stop",
				},
			},
		},
	}
	server := mockDockerServer(containers)
	defer server.Close()

	cfg := &config.Config{Rules: rules, Default: "deny", Upstream: server.URL}
	e := newTestEngineWithHTTP(cfg, server.URL)

	class := classifier.Classification{Action: "restart", Target: "container", ID: "app"}
	req := httptest.NewRequest("POST", "/containers/app/restart", nil)
	decision := e.Authorize(req, class, nil)
	if decision.Allowed {
		t.Fatal("expected invalid label rule to deny after static rules miss")
	}
	if !strings.Contains(decision.Reason, "invalid container label rule") {
		t.Fatalf("expected invalid label rule reason, got: %s", decision.Reason)
	}
}

func TestEngine_ContainerLabelExecRuleExactUser(t *testing.T) {
	containers := map[string]map[string]interface{}{
		"shell": {
			"Id":   "shellfull",
			"Name": "/shell-app",
			"Config": map[string]interface{}{
				"Image": "myapp",
				"Labels": map[string]interface{}{
					"dpp.rule.shell.action":    "exec",
					"dpp.rule.shell.match":     "*",
					"dpp.rule.shell.exec-user": "deploy:deploy",
				},
			},
		},
	}
	server := mockDockerServer(containers)
	defer server.Close()

	cfg := &config.Config{Default: "deny", Upstream: server.URL}
	e := newTestEngineWithHTTP(cfg, server.URL)

	class := classifier.Classification{Action: "exec", Target: "container", ID: "shell"}
	req := httptest.NewRequest("POST", "/containers/shell/exec", nil)

	decision := e.Authorize(req, class, []byte(`{"User":"deploy:deploy","Cmd":["sh"]}`))
	if !decision.Allowed {
		t.Errorf("expected label-defined exec rule to allow exact user, got: %s", decision.Reason)
	}

	decision = e.Authorize(req, class, []byte(`{"User":"deploy","Cmd":["sh"]}`))
	if decision.Allowed {
		t.Error("expected exact label-defined exec user to require full user:group match")
	}
}

func TestEngine_ContainerLabelExecRuleWithoutUserConfigDenied(t *testing.T) {
	containers := map[string]map[string]interface{}{
		"shell": {
			"Id":   "shellfull",
			"Name": "/shell-app",
			"Config": map[string]interface{}{
				"Image": "myapp",
				"Labels": map[string]interface{}{
					"dpp.rule.shell.action": "exec",
					"dpp.rule.shell.match":  "*",
				},
			},
		},
	}
	server := mockDockerServer(containers)
	defer server.Close()

	cfg := &config.Config{Default: "deny", Upstream: server.URL}
	e := newTestEngineWithHTTP(cfg, server.URL)

	class := classifier.Classification{Action: "exec", Target: "container", ID: "shell"}
	req := httptest.NewRequest("POST", "/containers/shell/exec", nil)
	decision := e.Authorize(req, class, []byte(`{"User":"1000","Cmd":["sh"]}`))
	if decision.Allowed {
		t.Error("expected label-defined exec rule without user config to deny")
	}
}

func TestEngine_ContainerLabelExecRuleAllowsFollowup(t *testing.T) {
	containers := map[string]map[string]interface{}{
		"shell": {
			"Id":   "shellfull",
			"Name": "/shell-app",
			"Config": map[string]interface{}{
				"Image": "myapp",
				"Labels": map[string]interface{}{
					"dpp.rule.shell.action":          "exec",
					"dpp.rule.shell.match":           "*",
					"dpp.rule.shell.exec-user-allow": "1000",
				},
			},
		},
	}
	server := mockDockerServer(containers)
	defer server.Close()

	cfg := &config.Config{Default: "deny", Upstream: server.URL}
	e := newTestEngineWithHTTP(cfg, server.URL)

	createClass := classifier.Classification{Action: "exec", Target: "container", ID: "shell"}
	createReq := httptest.NewRequest("POST", "/containers/shell/exec", nil)
	createDecision := e.Authorize(createReq, createClass, []byte(`{"User":"1000","Cmd":["sh"]}`))
	if !createDecision.Allowed {
		t.Fatalf("expected label-defined exec create to allow, got: %s", createDecision.Reason)
	}

	e.StoreExecID("exec123", "shell")
	followupClass := classifier.Classification{Action: "exec.start", Target: "container", ID: "exec123"}
	followupReq := httptest.NewRequest("POST", "/exec/exec123/start", nil)
	followupDecision := e.Authorize(followupReq, followupClass, nil)
	if !followupDecision.Allowed {
		t.Errorf("expected label-defined exec rule to allow exec.start followup, got: %s", followupDecision.Reason)
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

func mergeLabels(base, extra map[string]interface{}) map[string]interface{} {
	labels := map[string]interface{}{}
	for k, v := range base {
		labels[k] = v
	}
	for k, v := range extra {
		labels[k] = v
	}
	return labels
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

		// === Bug-revealing cases ===

		// Bug 1: Multi-wildcard patterns with '/' — only first '*' is split,
		// suffix retains literal '*' so HasSuffix fails.
		// Pattern "registry.io/*/image" should match "registry.io/org/image"
		{"registry.io/*/image", "registry.io/org/image", true},
		// Pattern "registry.io/*:*" should match "registry.io/app:latest"
		{"registry.io/*:*", "registry.io/app:latest", true},
		// Pattern "*backend*" — no '/' so filepath.Match handles it, should work
		{"*backend*", "my-backend-service", true},
		{"*backend*", "frontend", false},

		// Bug 4: '?' wildcard in patterns with '/' — falls through to exact match
		{"registry.io/app-?", "registry.io/app-1", true},
		{"registry.io/app-?", "registry.io/app-12", false},

		// Patterns with '/' and single '*' (the happy path that does work)
		{"registry.io/*", "registry.io/myapp:latest", true},
		{"registry.io/*", "other.io/myapp", false},

		// Edge: pattern with '/' and no wildcard — exact match
		{"registry.io/exact", "registry.io/exact", true},
		{"registry.io/exact", "registry.io/other", false},

		// Edge: empty pattern and value
		{"", "", true},
		{"*", "", true},
		{"", "notempty", false},

		// filepath.Match with bracket characters in pattern (returns ErrBadPattern → false)
		{"my[app", "my[app", false}, // malformed bracket = silent deny, arguably a bug
		// Backslash in pattern on Linux — '\a' matches literal 'a'
		{"my\\app", "myapp", true}, // filepath.Match treats \ as escape on non-Windows

		// Value with special chars (pattern is simple glob, value has brackets)
		{"my-*", "my-[weird]-app", true},

		// Suffix overlap: prefix+suffix together longer than value — should NOT match
		// "longprefix*longprefix.io" requires "longprefix" before * and "longprefix.io" after *
		// which is impossible when the value is shorter than both combined
		{"registry.io/longprefix*longprefix.io", "registry.io/longprefix.io", false},
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
