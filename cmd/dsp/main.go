// Docker Permission Proxy (DSP)
//
// A configurable Docker socket proxy that enforces fine-grained access control
// rules defined via environment variables using a Traefik-style naming convention.
package main

import (
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/danielvolz/docker-permission-proxy/internal/config"
	"github.com/danielvolz/docker-permission-proxy/internal/proxy"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Println("Docker Permission Proxy starting...")

	// Parse configuration from environment
	cfg, err := config.Parse()
	if err != nil {
		log.Fatalf("FATAL: failed to parse config: %v", err)
	}

	// Log configuration
	log.Printf("CONFIG listen=%s upstream=%s default=%s confirmSocket=%q confirmTimeout=%s rules=%d",
		cfg.Listen, cfg.Upstream, cfg.Default, cfg.ConfirmSocket, cfg.ConfirmTimeout, len(cfg.Rules))
	for _, r := range cfg.Rules {
		actions := make([]string, 0, len(r.Actions))
		for a := range r.Actions {
			actions = append(actions, a)
		}
		targets := make([]string, 0, len(r.Targets))
		for t := range r.Targets {
			targets = append(targets, t)
		}
		log.Printf("  RULE %s: decision=%s actions=[%s] targets=[%s] matchAny=%v labels=%v name=%q image=%q execUser=%q execUserAllow=%v",
			r.Name,
			r.Decision,
			strings.Join(actions, ","),
			strings.Join(targets, ","),
			r.MatchAny,
			r.MatchLabels,
			r.MatchName,
			r.MatchImage,
			r.ExecUser,
			r.ExecUserAllow,
		)
	}

	// Create handler
	handler := proxy.NewHandler(cfg)

	// Start server
	listener, err := createListener(cfg.Listen)
	if err != nil {
		log.Fatalf("FATAL: failed to create listener: %v", err)
	}
	defer listener.Close()

	log.Printf("Listening on %s", cfg.Listen)

	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		log.Fatalf("FATAL: server error: %v", err)
	}
}

// createListener creates a net.Listener based on the DPP_LISTEN config.
// Supported formats:
//   - unix:///path/to/socket
//   - tcp://host:port
//   - host:port (treated as tcp)
func createListener(listen string) (net.Listener, error) {
	switch {
	case strings.HasPrefix(listen, "unix://"):
		socketPath := strings.TrimPrefix(listen, "unix://")
		// Remove existing stale socket file if present.
		if info, err := os.Lstat(socketPath); err == nil {
			if info.Mode()&os.ModeSocket == 0 {
				return nil, os.ErrExist
			}
			if err := os.Remove(socketPath); err != nil {
				return nil, err
			}
		} else if !os.IsNotExist(err) {
			return nil, err
		}
		ln, err := net.Listen("unix", socketPath)
		if err != nil {
			return nil, err
		}
		// Make socket accessible
		if err := os.Chmod(socketPath, 0660); err != nil {
			ln.Close()
			return nil, err
		}
		log.Printf("Listening on unix socket: %s", socketPath)
		return ln, nil

	case strings.HasPrefix(listen, "tcp://"):
		addr := strings.TrimPrefix(listen, "tcp://")
		return net.Listen("tcp", addr)

	default:
		// Assume tcp
		return net.Listen("tcp", listen)
	}
}
