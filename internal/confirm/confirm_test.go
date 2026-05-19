package confirm

import (
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

func TestDesktop_AutoAllowDrainsPendingRequests(t *testing.T) {
	d := NewDesktop(time.Second)

	if d.beginRequest() {
		t.Fatal("first request should not auto-allow")
	}
	if d.beginRequest() {
		t.Fatal("second request should not auto-allow before approve-all")
	}

	d.enableAutoAllow()
	if !d.shouldAutoAllow() {
		t.Fatal("approve-all should enable auto-allow")
	}

	d.finishRequest()
	if !d.shouldAutoAllow() {
		t.Fatal("auto-allow should stay enabled while requests are still pending")
	}

	d.finishRequest()
	if d.shouldAutoAllow() {
		t.Fatal("auto-allow should reset once the pending queue is empty")
	}

	if d.beginRequest() {
		t.Fatal("new requests after the queue drained should require confirmation again")
	}
	d.finishRequest()
}

func TestHandleNotificationSignalApproveAll(t *testing.T) {
	signal := &dbus.Signal{
		Name: "org.freedesktop.Notifications.ActionInvoked",
		Body: []interface{}{uint32(42), "approve_all"},
	}

	action, done := handleNotificationSignal(signal, 42)
	if !done {
		t.Fatal("expected approve-all signal to finish the confirmation")
	}
	if action != "approve_all" {
		t.Fatalf("expected approve_all action, got %q", action)
	}
}
