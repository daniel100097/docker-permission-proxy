package confirm

import (
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

func TestDesktop_AutoApproveExpiresAfterWindow(t *testing.T) {
	d := NewDesktop(time.Second)
	d.AutoApproveWindow = 25 * time.Millisecond

	if d.shouldAutoApprove() {
		t.Fatal("new desktop confirmer should require confirmation")
	}

	d.enableAutoApprove()
	if !d.shouldAutoApprove() {
		t.Fatal("approve-next should enable auto approval")
	}

	time.Sleep(40 * time.Millisecond)
	if d.shouldAutoApprove() {
		t.Fatal("auto approval should expire after the configured window")
	}
}

func TestHandleNotificationSignalApproveNext30(t *testing.T) {
	signal := &dbus.Signal{
		Name: "org.freedesktop.Notifications.ActionInvoked",
		Body: []interface{}{uint32(42), "approve_next_30"},
	}

	action, done := handleNotificationSignal(signal, 42)
	if !done {
		t.Fatal("expected approve-next signal to finish the confirmation")
	}
	if action != "approve_next_30" {
		t.Fatalf("expected approve_next_30 action, got %q", action)
	}
}
