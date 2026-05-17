package authz

import (
	"context"
	"net"
	"net/http"
	"strings"
)

// upstreamClient creates an HTTP client that connects to the upstream Docker socket.
// Supports both unix:// and http:// (for testing) upstreams.
func upstreamClient(upstream string) *http.Client {
	if strings.HasPrefix(upstream, "unix://") {
		socketPath := strings.TrimPrefix(upstream, "unix://")
		transport := &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		}
		return &http.Client{Transport: transport}
	}
	// For http:// URLs (used in tests), use default transport
	return &http.Client{}
}

// upstreamURL returns the base URL for making requests to the upstream.
// For unix sockets, returns "http://docker"; for http URLs, returns the URL as-is.
func upstreamURL(upstream string) string {
	if strings.HasPrefix(upstream, "unix://") {
		return "http://docker"
	}
	return strings.TrimSuffix(upstream, "/")
}
