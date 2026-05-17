package authz

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"
)

// newUpstreamClient creates a reusable HTTP client that connects to the upstream Docker socket.
// Supports both unix:// and http:// (for testing) upstreams.
func newUpstreamClient(upstream string) *http.Client {
	if strings.HasPrefix(upstream, "unix://") {
		socketPath := strings.TrimPrefix(upstream, "unix://")
		transport := &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socketPath)
			},
			MaxIdleConns:        10,
			IdleConnTimeout:     90 * time.Second,
			DisableCompression:  true,
		}
		return &http.Client{Transport: transport, Timeout: 30 * time.Second}
	}
	// For http:// URLs (used in tests), use default transport with timeout
	return &http.Client{Timeout: 30 * time.Second}
}

// upstreamURL returns the base URL for making requests to the upstream.
// For unix sockets, returns "http://docker"; for http URLs, returns the URL as-is.
func upstreamURL(upstream string) string {
	if strings.HasPrefix(upstream, "unix://") {
		return "http://docker"
	}
	return strings.TrimSuffix(upstream, "/")
}
