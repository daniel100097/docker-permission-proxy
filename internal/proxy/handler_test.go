package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/danielvolz/docker-permission-proxy/internal/config"
	"github.com/danielvolz/docker-permission-proxy/internal/confirm"
)

// mockDocker creates a fake Docker daemon HTTP server.
func mockDocker(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Strip version prefix (e.g. /v1.43/)
		if len(path) > 2 && path[1] == 'v' {
			if idx := strings.Index(path[1:], "/"); idx > 0 {
				path = path[idx+1:]
			}
		}

		// Container list
		if path == "/containers/json" && r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]map[string]interface{}{
				{"Id": "abc123", "Names": []string{"/dev-app"}},
			})
			return
		}

		// Container inspect
		if strings.HasSuffix(path, "/json") && strings.Contains(path, "/containers/") {
			parts := strings.Split(strings.Trim(path, "/"), "/")
			if len(parts) >= 3 {
				id := parts[1]
				containers := map[string]map[string]interface{}{
					"dev-app": {
						"Id": "abc123full", "Name": "/dev-app",
						"Config": map[string]interface{}{
							"Image":  "myapp:latest",
							"Labels": map[string]interface{}{"team": "dev", "env": "staging"},
						},
					},
					"prod-app": {
						"Id": "def456full", "Name": "/prod-app",
						"Config": map[string]interface{}{
							"Image":  "myapp:latest",
							"Labels": map[string]interface{}{"team": "ops", "env": "prod"},
						},
					},
					"abc123": {
						"Id": "abc123full", "Name": "/dev-app",
						"Config": map[string]interface{}{
							"Image":  "myapp:latest",
							"Labels": map[string]interface{}{"team": "dev", "env": "staging"},
						},
					},
				}
				if data, ok := containers[id]; ok {
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(data)
					return
				}
			}
			http.NotFound(w, r)
			return
		}

		// Exec create
		if strings.HasSuffix(path, "/exec") && r.Method == "POST" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"Id": "exec-id-123"})
			return
		}

		// Exec start
		if strings.Contains(path, "/exec/") && strings.HasSuffix(path, "/start") {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Container start/stop/restart
		for _, action := range []string{"/start", "/stop", "/restart", "/kill"} {
			if strings.HasSuffix(path, action) && r.Method == "POST" {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}

		// Ping
		if path == "/_ping" {
			w.Write([]byte("OK"))
			return
		}

		// Version
		if path == "/version" {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"Version": "24.0.0"})
			return
		}

		// Default
		http.NotFound(w, r)
	}))
}

func setupTestProxy(t *testing.T, dockerServer *httptest.Server) *httptest.Server {
	t.Helper()

	// Set env vars for rules
	envs := map[string]string{
		"DPP_LISTEN":                        "tcp://127.0.0.1:0",
		"DPP_UPSTREAM":                      dockerServer.URL,
		"DPP_DEFAULT":                       "deny",
		"DPP_RULE_readall_ACTION":           "list,inspect,logs",
		"DPP_RULE_readall_TARGET":           "container,image,network,volume",
		"DPP_RULE_readall_MATCH":            "*",
		"DPP_RULE_devexec_ACTION":           "exec",
		"DPP_RULE_devexec_MATCH_LABEL_team": "dev",
		"DPP_RULE_devexec_EXEC_USER_ALLOW":  "1000,deploy",
		"DPP_RULE_opsctl_ACTION":            "start,stop,restart,kill",
		"DPP_RULE_opsctl_MATCH_LABEL_env":   "prod",
	}
	for k, v := range envs {
		os.Setenv(k, v)
		t.Cleanup(func() { os.Unsetenv(k) })
	}

	cfg, err := config.Parse()
	if err != nil {
		t.Fatalf("failed to parse config: %v", err)
	}
	// Override upstream to test server URL
	cfg.Upstream = dockerServer.URL

	handler := NewHandler(cfg)
	return httptest.NewServer(handler)
}

func TestProxy_SystemEndpoints(t *testing.T) {
	docker := mockDocker(t)
	defer docker.Close()

	proxy := setupTestProxy(t, docker)
	defer proxy.Close()

	tests := []struct {
		method string
		path   string
		status int
	}{
		{"GET", "/_ping", http.StatusOK},
		{"HEAD", "/_ping", http.StatusOK},
		{"GET", "/version", http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			req, _ := http.NewRequest(tt.method, proxy.URL+tt.path, nil)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tt.status {
				body, _ := io.ReadAll(resp.Body)
				t.Errorf("expected status %d, got %d: %s", tt.status, resp.StatusCode, body)
			}
		})
	}
}

func TestProxy_ListContainers_Allowed(t *testing.T) {
	docker := mockDocker(t)
	defer docker.Close()

	proxy := setupTestProxy(t, docker)
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/containers/json")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	var containers []map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&containers)
	if len(containers) == 0 {
		t.Error("expected containers in response")
	}
}

func TestProxy_InspectContainer_Allowed(t *testing.T) {
	docker := mockDocker(t)
	defer docker.Close()

	proxy := setupTestProxy(t, docker)
	defer proxy.Close()

	resp, err := http.Get(proxy.URL + "/containers/dev-app/json")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("expected 200, got %d: %s", resp.StatusCode, body)
	}
}

func TestProxy_StartContainer_DeniedByLabel(t *testing.T) {
	docker := mockDocker(t)
	defer docker.Close()

	proxy := setupTestProxy(t, docker)
	defer proxy.Close()

	// dev-app has env=staging, but opsctl rule requires env=prod
	req, _ := http.NewRequest("POST", proxy.URL+"/containers/dev-app/start", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("expected 403, got %d: %s", resp.StatusCode, body)
	}
}

func TestProxy_StartContainer_AllowedByLabel(t *testing.T) {
	docker := mockDocker(t)
	defer docker.Close()

	proxy := setupTestProxy(t, docker)
	defer proxy.Close()

	// prod-app has env=prod, matches opsctl rule
	req, _ := http.NewRequest("POST", proxy.URL+"/containers/prod-app/start", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("expected 204, got %d: %s", resp.StatusCode, body)
	}
}

func TestProxy_AskRule_ConfirmedAllowed(t *testing.T) {
	docker := mockDocker(t)
	defer docker.Close()

	fake := &fakeConfirmer{allow: true}
	cfg := &config.Config{
		Upstream:       docker.URL,
		Default:        "deny",
		ConfirmTimeout: 2 * time.Second,
		Rules: []*config.Rule{{
			Name:     "askrestart",
			Decision: config.DecisionAsk,
			Actions:  map[string]bool{"restart": true},
			Targets:  map[string]bool{"container": true},
			MatchAny: true,
		}},
	}
	handler := NewHandler(cfg)
	handler.confirmer = fake
	proxy := httptest.NewServer(handler)
	defer proxy.Close()

	req, _ := http.NewRequest("POST", proxy.URL+"/containers/prod-app/restart", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 204, got %d: %s", resp.StatusCode, body)
	}

	confirmReq := fake.last
	if confirmReq.Rule != "askrestart" {
		t.Fatalf("expected confirmation rule askrestart, got %s", confirmReq.Rule)
	}
	if !strings.Contains(confirmReq.Message, "docker container restart prod-app") {
		t.Fatalf("confirmation message did not contain command, got: %s", confirmReq.Message)
	}
}

func TestProxy_AskRule_RejectedDenied(t *testing.T) {
	docker := mockDocker(t)
	defer docker.Close()

	cfg := &config.Config{
		Upstream:       docker.URL,
		Default:        "deny",
		ConfirmTimeout: 2 * time.Second,
		Rules: []*config.Rule{{
			Name:     "askrestart",
			Decision: config.DecisionAsk,
			Actions:  map[string]bool{"restart": true},
			Targets:  map[string]bool{"container": true},
			MatchAny: true,
		}},
	}
	handler := NewHandler(cfg)
	handler.confirmer = &fakeConfirmer{allow: false}
	proxy := httptest.NewServer(handler)
	defer proxy.Close()

	req, _ := http.NewRequest("POST", proxy.URL+"/containers/prod-app/restart", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestProxy_AskRule_DialogErrorDenied(t *testing.T) {
	docker := mockDocker(t)
	defer docker.Close()

	cfg := &config.Config{
		Upstream: docker.URL,
		Default:  "deny",
		Rules: []*config.Rule{{
			Name:     "askrestart",
			Decision: config.DecisionAsk,
			Actions:  map[string]bool{"restart": true},
			Targets:  map[string]bool{"container": true},
			MatchAny: true,
		}},
	}
	handler := NewHandler(cfg)
	handler.confirmer = &fakeConfirmer{err: errFakeConfirm}
	proxy := httptest.NewServer(handler)
	defer proxy.Close()

	req, _ := http.NewRequest("POST", proxy.URL+"/containers/prod-app/restart", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestProxy_ExecCreate_Allowed(t *testing.T) {
	docker := mockDocker(t)
	defer docker.Close()

	proxy := setupTestProxy(t, docker)
	defer proxy.Close()

	// dev-app has team=dev, exec with user 1000 should be allowed
	body := `{"User": "1000", "Cmd": ["sh"]}`
	req, _ := http.NewRequest("POST", proxy.URL+"/containers/dev-app/exec", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Errorf("expected 200, got %d: %s", resp.StatusCode, respBody)
	}
}

func TestProxy_ExecCreate_DeniedWrongUser(t *testing.T) {
	docker := mockDocker(t)
	defer docker.Close()

	proxy := setupTestProxy(t, docker)
	defer proxy.Close()

	// dev-app has team=dev, but user 0 (root) is not in allow list
	body := `{"User": "0", "Cmd": ["sh"]}`
	req, _ := http.NewRequest("POST", proxy.URL+"/containers/dev-app/exec", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403, got %d", resp.StatusCode)
	}
}

func TestProxy_ExecCreate_DeniedEmptyUser(t *testing.T) {
	docker := mockDocker(t)
	defer docker.Close()

	proxy := setupTestProxy(t, docker)
	defer proxy.Close()

	body := `{"Cmd": ["sh"]}`
	req, _ := http.NewRequest("POST", proxy.URL+"/containers/dev-app/exec", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403, got %d", resp.StatusCode)
	}
}

func TestProxy_UnknownEndpoint_Denied(t *testing.T) {
	docker := mockDocker(t)
	defer docker.Close()

	proxy := setupTestProxy(t, docker)
	defer proxy.Close()

	req, _ := http.NewRequest("POST", proxy.URL+"/something/unknown", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403, got %d", resp.StatusCode)
	}
}

func TestProxy_VersionedPaths(t *testing.T) {
	docker := mockDocker(t)
	defer docker.Close()

	proxy := setupTestProxy(t, docker)
	defer proxy.Close()

	// Versioned container list should work
	resp, err := http.Get(proxy.URL + "/v1.43/containers/json")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("expected 200, got %d: %s", resp.StatusCode, body)
	}
}

func TestProxy_DeleteContainer_Denied(t *testing.T) {
	docker := mockDocker(t)
	defer docker.Close()

	proxy := setupTestProxy(t, docker)
	defer proxy.Close()

	// No rule allows "remove" action
	req, _ := http.NewRequest("DELETE", proxy.URL+"/containers/dev-app", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403, got %d", resp.StatusCode)
	}
}

var errFakeConfirm = errBodyTooLarge

type fakeConfirmer struct {
	allow bool
	err   error
	last  confirm.Request
}

func (f *fakeConfirmer) Ask(_ context.Context, req confirm.Request) (bool, error) {
	f.last = req
	return f.allow, f.err
}
