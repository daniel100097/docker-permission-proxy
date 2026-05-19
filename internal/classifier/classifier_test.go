package classifier

import (
	"testing"
)

func TestClassify_ContainerList(t *testing.T) {
	tests := []struct {
		method string
		path   string
		want   Classification
	}{
		{"GET", "/containers/json", Classification{"list", "container", ""}},
		{"GET", "/v1.43/containers/json", Classification{"list", "container", ""}},
		{"GET", "/v1.43/containers/json?all=true", Classification{"list", "container", ""}},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			got := Classify(tt.method, tt.path)
			assertClassification(t, got, tt.want)
		})
	}
}

func TestClassify_ContainerInspect(t *testing.T) {
	tests := []struct {
		method string
		path   string
		want   Classification
	}{
		{"GET", "/containers/abc123/json", Classification{"inspect", "container", "abc123"}},
		{"GET", "/v1.45/containers/mycontainer/json", Classification{"inspect", "container", "mycontainer"}},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := Classify(tt.method, tt.path)
			assertClassification(t, got, tt.want)
		})
	}
}

func TestClassify_ContainerLogs(t *testing.T) {
	got := Classify("GET", "/v1.43/containers/web01/logs")
	assertClassification(t, got, Classification{"logs", "container", "web01"})

	got = Classify("GET", "/containers/web01/logs?follow=true&stdout=true")
	assertClassification(t, got, Classification{"logs", "container", "web01"})
}

func TestClassify_ContainerExec(t *testing.T) {
	tests := []struct {
		name   string
		method string
		path   string
		want   Classification
	}{
		{"exec create", "POST", "/containers/abc123/exec", Classification{"exec", "container", "abc123"}},
		{"exec create versioned", "POST", "/v1.43/containers/abc123/exec", Classification{"exec", "container", "abc123"}},
		{"exec start", "POST", "/exec/execid123/start", Classification{"exec.start", "container", "execid123"}},
		{"exec start versioned", "POST", "/v1.43/exec/execid123/start", Classification{"exec.start", "container", "execid123"}},
		{"exec resize", "POST", "/exec/execid123/resize", Classification{"exec.resize", "container", "execid123"}},
		{"exec inspect", "GET", "/exec/execid123/json", Classification{"exec.inspect", "container", "execid123"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Classify(tt.method, tt.path)
			assertClassification(t, got, tt.want)
		})
	}
}

func TestClassify_ContainerLifecycle(t *testing.T) {
	tests := []struct {
		method string
		path   string
		action string
	}{
		{"POST", "/containers/abc/start", "start"},
		{"POST", "/containers/abc/stop", "stop"},
		{"POST", "/containers/abc/restart", "restart"},
		{"POST", "/containers/abc/kill", "kill"},
		{"POST", "/containers/abc/pause", "pause"},
		{"POST", "/containers/abc/unpause", "unpause"},
		{"POST", "/v1.43/containers/abc/start", "start"},
		{"DELETE", "/containers/abc", "remove"},
		{"DELETE", "/v1.43/containers/abc", "remove"},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			got := Classify(tt.method, tt.path)
			if got.Action != tt.action {
				t.Errorf("expected action %s, got %s", tt.action, got.Action)
			}
			if got.Target != "container" {
				t.Errorf("expected target container, got %s", got.Target)
			}
			if got.ID != "abc" {
				t.Errorf("expected ID abc, got %s", got.ID)
			}
		})
	}
}

func TestClassify_ContainerCreate(t *testing.T) {
	got := Classify("POST", "/containers/create")
	assertClassification(t, got, Classification{"create", "container", ""})

	got = Classify("POST", "/v1.43/containers/create?name=mycontainer")
	assertClassification(t, got, Classification{"create", "container", ""})
}

func TestClassify_ContainerAttach(t *testing.T) {
	got := Classify("POST", "/containers/abc/attach")
	assertClassification(t, got, Classification{"attach", "container", "abc"})

	got = Classify("GET", "/containers/abc/attach/ws")
	assertClassification(t, got, Classification{"attach", "container", "abc"})
}

func TestClassify_Images(t *testing.T) {
	tests := []struct {
		method string
		path   string
		want   Classification
	}{
		{"GET", "/images/json", Classification{"list", "image", ""}},
		{"GET", "/v1.43/images/json", Classification{"list", "image", ""}},
		{"GET", "/images/myimage/json", Classification{"inspect", "image", "myimage"}},
		{"GET", "/v1.54/images/otel/opentelemetry-collector-contrib:latest/json", Classification{"inspect", "image", "otel/opentelemetry-collector-contrib:latest"}},
		{"GET", "/v1.54/images/git.host-unlimited.de/host-unlimited/hosting-manager:develop/json", Classification{"inspect", "image", "git.host-unlimited.de/host-unlimited/hosting-manager:develop"}},
		{"POST", "/images/create", Classification{"pull", "image", ""}},
		{"POST", "/images/myimage/push", Classification{"push", "image", "myimage"}},
		{"POST", "/images/registry.example.com/team/myimage:latest/push", Classification{"push", "image", "registry.example.com/team/myimage:latest"}},
		{"POST", "/images/myimage/tag", Classification{"tag", "image", "myimage"}},
		{"DELETE", "/images/myimage", Classification{"remove", "image", "myimage"}},
		{"DELETE", "/images/registry.example.com/team/myimage:latest", Classification{"remove", "image", "registry.example.com/team/myimage:latest"}},
		{"POST", "/images/prune", Classification{"prune", "image", ""}},
		{"POST", "/build", Classification{"build", "image", ""}},
		{"POST", "/v1.43/build", Classification{"build", "image", ""}},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			got := Classify(tt.method, tt.path)
			assertClassification(t, got, tt.want)
		})
	}
}

func TestClassify_Networks(t *testing.T) {
	tests := []struct {
		method string
		path   string
		want   Classification
	}{
		{"GET", "/networks", Classification{"list", "network", ""}},
		{"GET", "/networks/mynet", Classification{"inspect", "network", "mynet"}},
		{"POST", "/networks/create", Classification{"network.create", "network", ""}},
		{"DELETE", "/networks/mynet", Classification{"network.remove", "network", "mynet"}},
		{"POST", "/networks/mynet/connect", Classification{"network.connect", "network", "mynet"}},
		{"POST", "/networks/mynet/disconnect", Classification{"network.disconnect", "network", "mynet"}},
		{"POST", "/networks/prune", Classification{"prune", "network", ""}},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			got := Classify(tt.method, tt.path)
			assertClassification(t, got, tt.want)
		})
	}
}

func TestClassify_Volumes(t *testing.T) {
	tests := []struct {
		method string
		path   string
		want   Classification
	}{
		{"GET", "/volumes", Classification{"list", "volume", ""}},
		{"GET", "/volumes/myvol", Classification{"inspect", "volume", "myvol"}},
		{"POST", "/volumes/create", Classification{"volume.create", "volume", ""}},
		{"DELETE", "/volumes/myvol", Classification{"volume.remove", "volume", "myvol"}},
		{"POST", "/volumes/prune", Classification{"prune", "volume", ""}},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			got := Classify(tt.method, tt.path)
			assertClassification(t, got, tt.want)
		})
	}
}

func TestClassify_System(t *testing.T) {
	tests := []struct {
		method string
		path   string
		action string
	}{
		{"GET", "/_ping", "ping"},
		{"HEAD", "/_ping", "ping"},
		{"GET", "/version", "version"},
		{"GET", "/info", "info"},
		{"GET", "/events", "events"},
		{"GET", "/system/df", "df"},
		{"GET", "/v1.43/_ping", "ping"},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			got := Classify(tt.method, tt.path)
			if got.Action != tt.action {
				t.Errorf("expected action %s, got %s", tt.action, got.Action)
			}
			if got.Target != "system" {
				t.Errorf("expected target system, got %s", got.Target)
			}
		})
	}
}

func TestClassify_Unknown(t *testing.T) {
	tests := []struct {
		method string
		path   string
	}{
		{"POST", "/unknown/endpoint"},
		{"GET", "/nonexistent"},
		{"PUT", "/containers/abc/json"},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			got := Classify(tt.method, tt.path)
			if got.Action != "unknown" {
				t.Errorf("expected unknown action, got %s", got.Action)
			}
		})
	}
}

func TestClassify_TrailingSlash(t *testing.T) {
	// Test that trailing slashes work
	got := Classify("GET", "/containers/json/")
	assertClassification(t, got, Classification{"list", "container", ""})

	got = Classify("POST", "/containers/abc/exec/")
	assertClassification(t, got, Classification{"exec", "container", "abc"})
}

func TestClassify_WithQueryString(t *testing.T) {
	got := Classify("GET", "/containers/json?all=true&size=true")
	assertClassification(t, got, Classification{"list", "container", ""})

	got = Classify("GET", "/containers/abc123/logs?follow=true&stdout=true&stderr=true")
	assertClassification(t, got, Classification{"logs", "container", "abc123"})
}

func TestClassify_ContainerPrune(t *testing.T) {
	got := Classify("POST", "/containers/prune")
	assertClassification(t, got, Classification{"prune", "container", ""})
}

func assertClassification(t *testing.T, got, want Classification) {
	t.Helper()
	if got.Action != want.Action {
		t.Errorf("Action: got %q, want %q", got.Action, want.Action)
	}
	if got.Target != want.Target {
		t.Errorf("Target: got %q, want %q", got.Target, want.Target)
	}
	if got.ID != want.ID {
		t.Errorf("ID: got %q, want %q", got.ID, want.ID)
	}
}
