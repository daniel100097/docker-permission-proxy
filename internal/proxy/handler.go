// Package proxy implements the HTTP reverse proxy to the Docker socket.
package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"path"
	"strings"
	"time"

	"github.com/danielvolz/docker-permission-proxy/internal/authz"
	"github.com/danielvolz/docker-permission-proxy/internal/classifier"
	"github.com/danielvolz/docker-permission-proxy/internal/config"
)

// Handler is the main HTTP handler for the proxy.
type Handler struct {
	engine   *authz.Engine
	proxy    *httputil.ReverseProxy
	upstream string
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
		engine:   engine,
		proxy:    proxy,
		upstream: upstream,
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
		body, err = io.ReadAll(io.LimitReader(req.Body, 10<<20)) // 10MB limit
		if err != nil {
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
