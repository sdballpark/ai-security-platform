package ratelimit

import (
	"testing"
	"time"
)

func TestBurstThenDenyThenRefill(t *testing.T) {
	l := New()
	now := time.Unix(0, 0)
	l.now = func() time.Time { return now }

	// burst=3, rps=1. First 3 allowed, 4th denied.
	for i := 0; i < 3; i++ {
		if !l.Allow("tA", 1, 3) {
			t.Fatalf("request %d should be allowed within burst", i)
		}
	}
	if l.Allow("tA", 1, 3) {
		t.Fatal("4th request should be denied (bucket empty)")
	}

	// Advance 1s → 1 token refilled → one more allowed.
	now = now.Add(time.Second)
	if !l.Allow("tA", 1, 3) {
		t.Fatal("after 1s refill, request should be allowed")
	}
}

func TestTenantIsolation(t *testing.T) {
	l := New()
	now := time.Unix(0, 0)
	l.now = func() time.Time { return now }

	// Drain tenant A entirely.
	for i := 0; i < 2; i++ {
		l.Allow("tA", 1, 2)
	}
	if l.Allow("tA", 1, 2) {
		t.Fatal("tenant A should be exhausted")
	}
	// Tenant B is unaffected — isolation holds.
	if !l.Allow("tB", 1, 2) {
		t.Fatal("tenant B must not be affected by tenant A's usage")
	}
}
