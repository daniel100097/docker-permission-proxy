// Package confirm contains desktop confirmation helpers.
package confirm

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
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

// Ask sends an actionable desktop notification and returns true only when the user confirms.
func (d *Desktop) Ask(_ context.Context, req Request) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), d.Timeout)
	defer cancel()

	message := req.Message
	if message == "" {
		message = fmt.Sprintf("%s %s", req.Method, req.Path)
	}

	conn, err := dbus.SessionBus()
	if err != nil {
		return false, fmt.Errorf("connect session bus: %w", err)
	}
	defer conn.Close()

	obj := conn.Object("org.freedesktop.Notifications", "/org/freedesktop/Notifications")
	capabilities, err := notificationCapabilities(obj)
	if err != nil {
		return false, err
	}
	if !capabilities["actions"] {
		return false, errors.New("desktop notification service does not support actions")
	}

	signals := make(chan *dbus.Signal, 10)
	conn.Signal(signals)
	defer conn.RemoveSignal(signals)

	if err := conn.AddMatchSignal(
		dbus.WithMatchInterface("org.freedesktop.Notifications"),
		dbus.WithMatchMember("ActionInvoked"),
	); err != nil {
		return false, fmt.Errorf("listen for notification actions: %w", err)
	}
	if err := conn.AddMatchSignal(
		dbus.WithMatchInterface("org.freedesktop.Notifications"),
		dbus.WithMatchMember("NotificationClosed"),
	); err != nil {
		return false, fmt.Errorf("listen for notification close: %w", err)
	}

	notificationID, err := sendNotification(obj, req, message, d.Timeout)
	if err != nil {
		return false, err
	}
	defer obj.Call("org.freedesktop.Notifications.CloseNotification", 0, notificationID)

	for {
		select {
		case <-ctx.Done():
			return false, fmt.Errorf("confirmation timed out: %w", ctx.Err())
		case signal := <-signals:
			allowed, done := handleNotificationSignal(signal, notificationID)
			if done {
				return allowed, nil
			}
		}
	}
}

func notificationCapabilities(obj dbus.BusObject) (map[string]bool, error) {
	var caps []string
	if err := obj.Call("org.freedesktop.Notifications.GetCapabilities", 0).Store(&caps); err != nil {
		return nil, fmt.Errorf("read notification capabilities: %w", err)
	}
	result := map[string]bool{}
	for _, cap := range caps {
		result[cap] = true
	}
	return result, nil
}

func sendNotification(obj dbus.BusObject, req Request, message string, timeout time.Duration) (uint32, error) {
	actions := []string{"approve", "Approve", "deny", "Deny"}
	hints := map[string]dbus.Variant{
		"resident":  dbus.MakeVariant(true),
		"transient": dbus.MakeVariant(false),
	}

	summary := "Docker Permission Proxy"
	if req.Command != "" {
		summary = "Confirm: " + req.Command
	}

	var id uint32
	call := obj.Call(
		"org.freedesktop.Notifications.Notify",
		0,
		"Docker Permission Proxy",
		uint32(0),
		"dialog-question",
		summary,
		message,
		actions,
		hints,
		int32(timeout/time.Millisecond),
	)
	if call.Err != nil {
		return 0, fmt.Errorf("send desktop notification: %w", call.Err)
	}
	if err := call.Store(&id); err != nil {
		return 0, fmt.Errorf("read desktop notification id: %w", err)
	}
	return id, nil
}

func handleNotificationSignal(signal *dbus.Signal, notificationID uint32) (bool, bool) {
	if signal == nil || len(signal.Body) < 1 {
		return false, false
	}

	id, ok := signal.Body[0].(uint32)
	if !ok || id != notificationID {
		return false, false
	}

	switch signal.Name {
	case "org.freedesktop.Notifications.ActionInvoked":
		if len(signal.Body) < 2 {
			return false, true
		}
		action, _ := signal.Body[1].(string)
		return action == "approve", true
	case "org.freedesktop.Notifications.NotificationClosed":
		return false, true
	default:
		return false, false
	}
}
