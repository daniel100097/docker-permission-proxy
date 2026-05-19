// Package confirm contains desktop confirmation helpers.
package confirm

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"sync"
	"time"
)

// Request describes one Docker API operation that needs confirmation.
type Request struct {
	ID         string                 `json:"id"`
	Rule       string                 `json:"rule"`
	Action     string                 `json:"action"`
	Target     string                 `json:"target"`
	ResourceID string                 `json:"resource_id,omitempty"`
	Method     string                 `json:"method"`
	Path       string                 `json:"path"`
	RawQuery   string                 `json:"raw_query,omitempty"`
	Command    string                 `json:"command,omitempty"`
	Message    string                 `json:"message"`
	Details    map[string]interface{} `json:"details,omitempty"`
}

// Confirmer asks whether a confirmation request should be allowed.
type Confirmer interface {
	Ask(ctx context.Context, req Request) (bool, error)
}

// Desktop asks through a desktop dialog inside the current process environment.
type Desktop struct {
	Timeout time.Duration
	mu      sync.Mutex
}

// NewDesktop creates a desktop dialog confirmer.
func NewDesktop(timeout time.Duration) *Desktop {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &Desktop{Timeout: timeout}
}

// Ask opens kdialog or zenity and returns true only when the user confirms.
func (d *Desktop) Ask(_ context.Context, req Request) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), d.Timeout)
	defer cancel()

	message := req.Message
	if message == "" {
		message = fmt.Sprintf("%s %s", req.Method, req.Path)
	}

	if path, ok := lookup("kdialog"); ok {
		return runQuestion(exec.CommandContext(ctx, path, "--title", "Docker Permission Proxy", "--yesno", message))
	}
	if path, ok := lookup("zenity"); ok {
		return runQuestion(exec.CommandContext(ctx, path, "--question", "--title", "Docker Permission Proxy", "--width", "640", "--text", message))
	}

	return false, errors.New("neither kdialog nor zenity was found in PATH")
}

func runQuestion(cmd *exec.Cmd) (bool, error) {
	err := cmd.Run()
	if err == nil {
		return true, nil
	}
	if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
		return false, nil
	}
	return false, err
}

func lookup(name string) (string, bool) {
	path, err := exec.LookPath(name)
	return path, err == nil
}
