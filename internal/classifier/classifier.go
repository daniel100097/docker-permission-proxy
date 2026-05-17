// Package classifier maps HTTP method+path to action, target, and resource ID.
package classifier

import (
	"regexp"
	"strings"
)

// Classification holds the result of classifying a Docker API request.
type Classification struct {
	Action string // e.g. "list", "inspect", "exec", "start", "stop", "create", etc.
	Target string // e.g. "container", "image", "network", "volume"
	ID     string // resource ID (container/image/network/volume ID or name), empty for list/create
}

// route defines a pattern to match against.
type route struct {
	method  string
	pattern *regexp.Regexp
	action  string
	target  string
	idGroup int // capture group index for ID (-1 if none)
}

var routes []route

func init() {
	// The version prefix is optional: /v1.43/containers/json or /containers/json
	vp := `(?:/v[\d.]+)?`

	routes = []route{
		// Container operations
		{method: "GET", pattern: re(vp + `/containers/json/?`), action: "list", target: "container", idGroup: -1},
		{method: "GET", pattern: re(vp + `/containers/([^/]+)/json/?`), action: "inspect", target: "container", idGroup: 1},
		{method: "GET", pattern: re(vp + `/containers/([^/]+)/logs/?`), action: "logs", target: "container", idGroup: 1},
		{method: "GET", pattern: re(vp + `/containers/([^/]+)/top/?`), action: "inspect", target: "container", idGroup: 1},
		{method: "GET", pattern: re(vp + `/containers/([^/]+)/stats/?`), action: "inspect", target: "container", idGroup: 1},
		{method: "GET", pattern: re(vp + `/containers/([^/]+)/changes/?`), action: "inspect", target: "container", idGroup: 1},
		{method: "GET", pattern: re(vp + `/containers/([^/]+)/export/?`), action: "inspect", target: "container", idGroup: 1},

		// Container exec
		{method: "POST", pattern: re(vp + `/containers/([^/]+)/exec/?`), action: "exec", target: "container", idGroup: 1},
		{method: "POST", pattern: re(vp + `/exec/([^/]+)/start/?`), action: "exec.start", target: "container", idGroup: 1},
		{method: "POST", pattern: re(vp + `/exec/([^/]+)/resize/?`), action: "exec.resize", target: "container", idGroup: 1},
		{method: "GET", pattern: re(vp + `/exec/([^/]+)/json/?`), action: "exec.inspect", target: "container", idGroup: 1},

		// Container attach
		{method: "POST", pattern: re(vp + `/containers/([^/]+)/attach/?`), action: "attach", target: "container", idGroup: 1},
		{method: "GET", pattern: re(vp + `/containers/([^/]+)/attach/ws/?`), action: "attach", target: "container", idGroup: 1},

		// Container lifecycle
		{method: "POST", pattern: re(vp + `/containers/([^/]+)/start/?`), action: "start", target: "container", idGroup: 1},
		{method: "POST", pattern: re(vp + `/containers/([^/]+)/stop/?`), action: "stop", target: "container", idGroup: 1},
		{method: "POST", pattern: re(vp + `/containers/([^/]+)/restart/?`), action: "restart", target: "container", idGroup: 1},
		{method: "POST", pattern: re(vp + `/containers/([^/]+)/kill/?`), action: "kill", target: "container", idGroup: 1},
		{method: "POST", pattern: re(vp + `/containers/([^/]+)/pause/?`), action: "pause", target: "container", idGroup: 1},
		{method: "POST", pattern: re(vp + `/containers/([^/]+)/unpause/?`), action: "unpause", target: "container", idGroup: 1},
		{method: "POST", pattern: re(vp + `/containers/([^/]+)/wait/?`), action: "wait", target: "container", idGroup: 1},
		{method: "POST", pattern: re(vp + `/containers/([^/]+)/rename/?`), action: "rename", target: "container", idGroup: 1},
		{method: "POST", pattern: re(vp + `/containers/([^/]+)/update/?`), action: "update", target: "container", idGroup: 1},
		{method: "DELETE", pattern: re(vp + `/containers/([^/]+)/?`), action: "remove", target: "container", idGroup: 1},

		// Container create
		{method: "POST", pattern: re(vp + `/containers/create/?`), action: "create", target: "container", idGroup: -1},

		// Container prune
		{method: "POST", pattern: re(vp + `/containers/prune/?`), action: "prune", target: "container", idGroup: -1},

		// Image operations
		{method: "GET", pattern: re(vp + `/images/json/?`), action: "list", target: "image", idGroup: -1},
		{method: "GET", pattern: re(vp + `/images/([^/]+)/json/?`), action: "inspect", target: "image", idGroup: 1},
		{method: "POST", pattern: re(vp + `/images/create/?`), action: "pull", target: "image", idGroup: -1},
		{method: "POST", pattern: re(vp + `/images/([^/]+)/push/?`), action: "push", target: "image", idGroup: 1},
		{method: "POST", pattern: re(vp + `/images/([^/]+)/tag/?`), action: "tag", target: "image", idGroup: 1},
		{method: "DELETE", pattern: re(vp + `/images/([^/]+)/?`), action: "remove", target: "image", idGroup: 1},
		{method: "POST", pattern: re(vp + `/images/prune/?`), action: "prune", target: "image", idGroup: -1},
		{method: "POST", pattern: re(vp + `/build/?`), action: "build", target: "image", idGroup: -1},

		// Network operations
		{method: "GET", pattern: re(vp + `/networks/?`), action: "list", target: "network", idGroup: -1},
		{method: "GET", pattern: re(vp + `/networks/([^/]+)/?`), action: "inspect", target: "network", idGroup: 1},
		{method: "POST", pattern: re(vp + `/networks/create/?`), action: "network.create", target: "network", idGroup: -1},
		{method: "DELETE", pattern: re(vp + `/networks/([^/]+)/?`), action: "network.remove", target: "network", idGroup: 1},
		{method: "POST", pattern: re(vp + `/networks/([^/]+)/connect/?`), action: "network.connect", target: "network", idGroup: 1},
		{method: "POST", pattern: re(vp + `/networks/([^/]+)/disconnect/?`), action: "network.disconnect", target: "network", idGroup: 1},
		{method: "POST", pattern: re(vp + `/networks/prune/?`), action: "prune", target: "network", idGroup: -1},

		// Volume operations
		{method: "GET", pattern: re(vp + `/volumes/?`), action: "list", target: "volume", idGroup: -1},
		{method: "GET", pattern: re(vp + `/volumes/([^/]+)/?`), action: "inspect", target: "volume", idGroup: 1},
		{method: "POST", pattern: re(vp + `/volumes/create/?`), action: "volume.create", target: "volume", idGroup: -1},
		{method: "DELETE", pattern: re(vp + `/volumes/([^/]+)/?`), action: "volume.remove", target: "volume", idGroup: 1},
		{method: "POST", pattern: re(vp + `/volumes/prune/?`), action: "prune", target: "volume", idGroup: -1},

		// System
		{method: "GET", pattern: re(vp + `/_ping/?`), action: "ping", target: "system", idGroup: -1},
		{method: "HEAD", pattern: re(vp + `/_ping/?`), action: "ping", target: "system", idGroup: -1},
		{method: "GET", pattern: re(vp + `/version/?`), action: "version", target: "system", idGroup: -1},
		{method: "GET", pattern: re(vp + `/info/?`), action: "info", target: "system", idGroup: -1},
		{method: "GET", pattern: re(vp + `/events/?`), action: "events", target: "system", idGroup: -1},
		{method: "GET", pattern: re(vp + `/system/df/?`), action: "df", target: "system", idGroup: -1},
	}
}

func re(pattern string) *regexp.Regexp {
	return regexp.MustCompile("^" + pattern + `(\?.*)?$`)
}

// Classify determines the action, target, and resource ID from an HTTP request.
func Classify(method, path string) Classification {
	// Strip query string for matching
	cleanPath := path
	if idx := strings.IndexByte(path, '?'); idx >= 0 {
		cleanPath = path[:idx]
	}

	for _, r := range routes {
		if r.method != method {
			continue
		}
		matches := r.pattern.FindStringSubmatch(cleanPath)
		if matches == nil {
			continue
		}

		c := Classification{
			Action: r.action,
			Target: r.target,
		}
		if r.idGroup > 0 && r.idGroup < len(matches) {
			c.ID = matches[r.idGroup]
		}
		return c
	}

	return Classification{Action: "unknown", Target: "unknown"}
}
