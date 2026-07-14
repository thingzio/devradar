package main

import "testing"

func TestRunFailsClosedWithoutDeliveryKey(t *testing.T) {
	t.Setenv("DEVRADAR_DELIVERY_KEY", "")
	t.Setenv("SEND_API_KEY", "")
	t.Setenv("DEVRADAR_DEV_MODE", "true")
	if got := run(); got != 1 {
		t.Fatalf("run exit code = %d, want 1", got)
	}
}
