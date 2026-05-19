// Package proxy implements the HTTP reverse proxy to the Docker socket.
package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/danielvolz/docker-permission-proxy/internal/authz"
	"github.com/danielvolz/docker-permission-proxy/internal/classifier"
	"github.com/danielvolz/docker-permission-proxy/internal/config"
	"github.com/danielvolz/docker-permission-proxy/internal/confirm"
)

const maxInspectedBodySize = 10 << 20 // 10MB

var errBodyTooLarge = errors.New("request body too large")

// Handler is the main HTTP handler for the proxy.
type Handler struct {
	engine    *authz.Engine
	proxy     *httputil.ReverseProxy
	upstream  string
	confirmer confirm.Confirmer
}

// NewHandler creates a new proxy handler.
func NewHandler(cfg *config.Config) *Handler {
	engine := authz.NewEngine(cfg)

	upstream := cfg.Upstream

	var proxy *httputil.ReverseProxy

	if strings.HasPrefix(upstream, "unix://") {
		socketPath := strings.TrimPrefix(upstream, "unix://")
		proxy = &httputil.ReverseProxy{
			Director: func(req *http.Request) {
				req.URL.Scheme = "http"
				req.URL.Host = "docker"
				req.Host = "docker"
			},
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", socketPath)
				},
				ResponseHeaderTimeout: 0,
				IdleConnTimeout:       90 * time.Second,
			},
			ModifyResponse: nil,
			FlushInterval:  -1,
		}
	} else {
		// HTTP upstream (for testing)
		proxy = &httputil.ReverseProxy{
			Director: func(req *http.Request) {
				req.URL.Scheme = "http"
				req.URL.Host = strings.TrimPrefix(upstream, "http://")
				req.Host = req.URL.Host
			},
			FlushInterval: -1,
		}
	}

	return &Handler{
		engine:    engine,
		proxy:     proxy,
		upstream:  upstream,
		confirmer: confirm.NewDesktop(cfg.ConfirmTimeout),
	}
}

// ServeHTTP handles incoming HTTP requests.
func (h *Handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	start := time.Now()

	// Normalize the path to prevent bypass via //, /../, etc.
	cleanedPath := path.Clean(req.URL.Path)
	if cleanedPath == "." {
		cleanedPath = "/"
	}
	req.URL.Path = cleanedPath

	// Classify the request
	class := classifier.Classify(req.Method, cleanedPath)
	log.Printf("REQ %s %s → action=%s target=%s id=%s", req.Method, cleanedPath, class.Action, class.Target, class.ID)

	// Read body for POST requests that need authorization inspection
	var body []byte
	if req.Method == "POST" && needsBodyInspection(class.Action) {
		var err error
		body, err = readLimited(req.Body, maxInspectedBodySize)
		if err != nil {
			if err == errBodyTooLarge {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "failed to read request body", http.StatusBadRequest)
			return
		}
		req.Body.Close()
		// Restore body for forwarding
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))
	}

	// Authorize
	decision := h.engine.Authorize(req, class, body)

	if decision.NeedsConfirmation {
		confirmReq := h.confirmationRequest(req, class, decision, body)
		ok, err := h.confirmer.Ask(req.Context(), confirmReq)
		if err != nil {
			log.Printf("DENY %s %s (confirmation failed: %v) [%s]", req.Method, cleanedPath, err, time.Since(start))
			http.Error(w, "confirmation failed\n", http.StatusForbidden)
			return
		}
		if !ok {
			log.Printf("DENY %s %s (confirmation rejected by rule %q) [%s]", req.Method, cleanedPath, decision.RuleName, time.Since(start))
			http.Error(w, "confirmation rejected\n", http.StatusForbidden)
			return
		}
		decision.Allowed = true
		decision.Reason = fmt.Sprintf("confirmed rule %q", decision.RuleName)
	}

	if !decision.Allowed {
		log.Printf("DENY %s %s (%s) [%s]", req.Method, cleanedPath, decision.Reason, time.Since(start))
		http.Error(w, "forbidden\n", http.StatusForbidden)
		return
	}

	log.Printf("ALLOW %s %s (%s) [%s]", req.Method, cleanedPath, decision.Reason, time.Since(start))

	// For exec create, capture the response to store the exec-id mapping
	if class.Action == "exec" && req.Method == "POST" {
		h.handleExecCreate(w, req, class.ID)
		return
	}

	// Check if this is an upgrade request (only allowed for attach/exec start)
	if isUpgradeRequest(req) && isUpgradeAllowed(class.Action) {
		h.handleUpgrade(w, req)
		return
	}

	// Forward to upstream
	h.proxy.ServeHTTP(w, req)
}

func readLimited(r io.Reader, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, errBodyTooLarge
	}
	return body, nil
}

func (h *Handler) confirmationRequest(req *http.Request, class classifier.Classification, decision authz.Decision, body []byte) confirm.Request {
	bodyMap := map[string]interface{}{}
	if len(body) > 0 {
		_ = json.Unmarshal(body, &bodyMap)
	}

	command := describeCommand(req, class, bodyMap)
	details := map[string]interface{}{
		"docker_api": fmt.Sprintf("%s %s", req.Method, req.URL.RequestURI()),
	}
	if command != "" {
		details["command"] = command
	}
	if decision.Container != nil {
		details["container_name"] = strings.TrimPrefix(decision.Container.Name, "/")
		details["container_image"] = decision.Container.Image
	}
	if user, ok := bodyMap["User"].(string); ok {
		details["exec_user"] = user
	}
	if image, ok := bodyMap["Image"].(string); ok {
		details["image"] = image
	}
	if cmd := commandFromBody(bodyMap); cmd != "" {
		details["body_cmd"] = cmd
	}

	lines := []string{
		"Docker Permission Proxy asks for confirmation.",
		"",
		fmt.Sprintf("Rule: %s", decision.RuleName),
		fmt.Sprintf("Request: %s %s", req.Method, req.URL.RequestURI()),
		fmt.Sprintf("Action: %s %s", class.Action, class.Target),
	}
	if class.ID != "" {
		lines = append(lines, fmt.Sprintf("Target ID: %s", class.ID))
	}
	if command != "" {
		lines = append(lines, fmt.Sprintf("Command: %s", command))
	}

	return confirm.Request{
		ID:         strconv.FormatInt(time.Now().UnixNano(), 36),
		Rule:       decision.RuleName,
		Action:     class.Action,
		Target:     class.Target,
		ResourceID: class.ID,
		Method:     req.Method,
		Path:       req.URL.Path,
		RawQuery:   req.URL.RawQuery,
		Command:    command,
		Message:    strings.Join(lines, "\n"),
		Details:    details,
	}
}

func describeCommand(req *http.Request, class classifier.Classification, body map[string]interface{}) string {
	switch class.Target {
	case "container":
		return describeContainerCommand(req, class, body)
	case "image":
		return describeImageCommand(req, class)
	case "volume":
		return describeObjectCommand("docker volume", class.Action, class.ID)
	case "network":
		return describeObjectCommand("docker network", class.Action, class.ID)
	default:
		if class.ID != "" {
			return fmt.Sprintf("docker %s %s %s", class.Target, class.Action, class.ID)
		}
		return fmt.Sprintf("docker %s %s", class.Target, class.Action)
	}
}

func describeContainerCommand(req *http.Request, class classifier.Classification, body map[string]interface{}) string {
	switch class.Action {
	case "exec":
		cmd := commandFromBody(body)
		user, _ := body["User"].(string)
		parts := []string{"docker exec"}
		if user != "" {
			parts = append(parts, "--user "+shellWord(user))
		}
		if class.ID != "" {
			parts = append(parts, shellWord(class.ID))
		}
		if cmd != "" {
			parts = append(parts, cmd)
		}
		return strings.Join(parts, " ")
	case "create":
		image, _ := body["Image"].(string)
		name := req.URL.Query().Get("name")
		parts := []string{"docker container create"}
		if name != "" {
			parts = append(parts, "--name "+shellWord(name))
		}
		if image != "" {
			parts = append(parts, shellWord(image))
		}
		if cmd := commandFromBody(body); cmd != "" {
			parts = append(parts, cmd)
		}
		return strings.Join(parts, " ")
	case "start", "stop", "restart", "kill", "pause", "unpause", "wait", "rename", "update", "remove":
		return describeObjectCommand("docker container", class.Action, class.ID)
	case "archive.write":
		return "docker cp <client path> " + shellWord(class.ID) + ":<container path>"
	case "archive.read":
		return "docker cp " + shellWord(class.ID) + ":<container path> <client path>"
	default:
		return describeObjectCommand("docker container", class.Action, class.ID)
	}
}

func describeImageCommand(req *http.Request, class classifier.Classification) string {
	switch class.Action {
	case "pull":
		ref := req.URL.Query().Get("fromImage")
		if tag := req.URL.Query().Get("tag"); ref != "" && tag != "" {
			ref += ":" + tag
		}
		return describeObjectCommand("docker image pull", "", ref)
	case "remove":
		return describeObjectCommand("docker image rm", "", class.ID)
	case "tag":
		return describeObjectCommand("docker image tag", "", class.ID)
	default:
		return describeObjectCommand("docker image", class.Action, class.ID)
	}
}

func describeObjectCommand(prefix, action, id string) string {
	parts := []string{prefix}
	if action != "" {
		parts = append(parts, action)
	}
	if id != "" {
		parts = append(parts, shellWord(id))
	}
	return strings.Join(parts, " ")
}

func commandFromBody(body map[string]interface{}) string {
	cmd, ok := body["Cmd"]
	if !ok {
		return ""
	}
	switch v := cmd.(type) {
	case []interface{}:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				parts = append(parts, shellWord(s))
			}
		}
		return strings.Join(parts, " ")
	case []string:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			parts = append(parts, shellWord(item))
		}
		return strings.Join(parts, " ")
	case string:
		return shellWord(v)
	default:
		return ""
	}
}

func shellWord(s string) string {
	if s == "" {
		return "''"
	}
	if !strings.ContainsAny(s, " \t\n'\"\\$`;&|<>*?()[]{}!") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// handleExecCreate intercepts exec create responses to capture the exec ID.
func (h *Handler) handleExecCreate(w http.ResponseWriter, req *http.Request, containerID string) {
	// Use a response recorder to capture the response
	rec := &responseRecorder{
		ResponseWriter: w,
		body:           &bytes.Buffer{},
	}

	h.proxy.ServeHTTP(rec, req)

	// Try to extract exec ID from response
	statusCode := rec.statusCode
	if statusCode == 0 {
		statusCode = http.StatusOK // default if WriteHeader never called
	}
	if statusCode >= 200 && statusCode < 300 {
		var execResp struct {
			ID string `json:"Id"`
		}
		if err := json.Unmarshal(rec.body.Bytes(), &execResp); err == nil && execResp.ID != "" {
			h.engine.StoreExecID(execResp.ID, containerID)
			shortID := execResp.ID
			if len(shortID) > 12 {
				shortID = shortID[:12]
			}
			log.Printf("EXEC-MAP %s → container %s", shortID, containerID)
		}
	}
}

// handleUpgrade handles connection upgrade for attach/exec websocket connections.
func (h *Handler) handleUpgrade(w http.ResponseWriter, req *http.Request) {
	// Hijack the client connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		log.Printf("ERROR: hijack failed: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// Connect to upstream
	var upstreamConn net.Conn
	if strings.HasPrefix(h.upstream, "unix://") {
		socketPath := strings.TrimPrefix(h.upstream, "unix://")
		upstreamConn, err = net.DialTimeout("unix", socketPath, 30*time.Second)
	} else {
		host := strings.TrimPrefix(h.upstream, "http://")
		upstreamConn, err = net.DialTimeout("tcp", host, 30*time.Second)
	}
	if err != nil {
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer upstreamConn.Close()

	// Write the original request to upstream (set Host like Director would)
	req.URL.Scheme = "http"
	req.URL.Host = "docker"
	req.Host = "docker"
	if err := req.Write(upstreamConn); err != nil {
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}

	// Bidirectional copy — wait for both goroutines
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(upstreamConn, clientConn)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(clientConn, upstreamConn)
		done <- struct{}{}
	}()
	<-done
	// Close connections to unblock the other goroutine
	clientConn.Close()
	upstreamConn.Close()
	<-done
}

// needsBodyInspection returns true if the action requires reading the request body.
func needsBodyInspection(action string) bool {
	switch action {
	case "exec", "create":
		return true
	default:
		return false
	}
}

// isUpgradeRequest checks if the request is a connection upgrade (websocket/raw stream).
func isUpgradeRequest(req *http.Request) bool {
	return strings.EqualFold(req.Header.Get("Upgrade"), "tcp") ||
		strings.EqualFold(req.Header.Get("Connection"), "Upgrade")
}

// isUpgradeAllowed checks if the action supports connection upgrades.
func isUpgradeAllowed(action string) bool {
	switch action {
	case "attach", "exec.start":
		return true
	default:
		return false
	}
}

// responseRecorder captures the response while also writing to the client.
type responseRecorder struct {
	http.ResponseWriter
	body       *bytes.Buffer
	statusCode int
	written    bool
}

func (r *responseRecorder) WriteHeader(code int) {
	r.statusCode = code
	r.ResponseWriter.WriteHeader(code)
	r.written = true
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	r.body.Write(b)
	return r.ResponseWriter.Write(b)
}
