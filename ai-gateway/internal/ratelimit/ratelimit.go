// Package ratelimit provides a per-key token-bucket limiter. Per-key buckets are
// the mechanism of tenant isolation at the rate layer: one tenant's burst cannot
// drain another tenant's quota.
package ratelimit

import (
	"sync"
	"time"
)

type bucket struct {
	tokens float64
	last   time.Time
}

type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	now     func() time.Time // injectable for deterministic tests
}

func New() *Limiter {
	return &Limiter{buckets: make(map[string]*bucket), now: time.Now}
}

// Allow consumes one token for key, refilling at rps up to burst. Returns false
// when the tenant has exhausted its allowance.
func (l *Limiter) Allow(key string, rps, burst float64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: burst, last: now}
		l.buckets[key] = b
	}
	// Refill based on elapsed wall time, capped at burst.
	b.tokens += now.Sub(b.last).Seconds() * rps
	if b.tokens > burst {
		b.tokens = burst
	}
	b.last = now

	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}
