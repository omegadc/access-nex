package server

// Minimal in-memory sliding-window rate limiter, keyed by client IP.

import (
	"net"
	"net/http"
	"sync"
	"time"
)

type rateLimiter struct {
	mu     sync.Mutex
	window time.Duration
	max    int
	hits   map[string][]time.Time
}

func newRateLimiter(max int, window time.Duration) *rateLimiter {
	return &rateLimiter{window: window, max: max, hits: make(map[string][]time.Time)}
}

// allow records a hit for key and reports whether it is within the limit.
func (rl *rateLimiter) allow(key string) bool {
	now := time.Now()
	cutoff := now.Add(-rl.window)

	rl.mu.Lock()
	defer rl.mu.Unlock()

	recent := rl.hits[key][:0]
	for _, t := range rl.hits[key] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	if len(recent) >= rl.max {
		rl.hits[key] = recent
		return false
	}
	rl.hits[key] = append(recent, now)

	// Opportunistic cleanup so the map does not grow without bound.
	if len(rl.hits) > 10000 {
		for k, ts := range rl.hits {
			if len(ts) == 0 || !ts[len(ts)-1].After(cutoff) {
				delete(rl.hits, k)
			}
		}
	}
	return true
}

// clientIP extracts the remote host without the port.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
