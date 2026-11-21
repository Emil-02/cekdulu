// Package ratelimit provides a small in-memory, per-key rate limiter.
package ratelimit

import (
	"sync"
	"time"
)

// Rate is a request budget: N requests per Per.
type Rate struct {
	N   int
	Per time.Duration
}

// Limiter is a fixed-window, per-key rate limiter kept in memory. It is good
// enough for a single instance; put a shared limiter in front when running
// several instances.
type Limiter struct {
	mu   sync.Mutex
	rate Rate
	now  func() time.Time
	hits map[string]*window
}

type window struct {
	start time.Time
	n     int
}

// New returns a limiter. now defaults to time.Now.
func New(r Rate, now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	return &Limiter{rate: r, now: now, hits: map[string]*window{}}
}

// Rate returns the configured budget.
func (l *Limiter) Rate() Rate { return l.rate }

// Allow records a hit for key and reports whether it is within budget. A nil
// limiter or one with N <= 0 allows everything.
func (l *Limiter) Allow(key string) bool {
	if l == nil || l.rate.N <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if len(l.hits) > 10000 {
		for k, w := range l.hits {
			if now.Sub(w.start) >= l.rate.Per {
				delete(l.hits, k)
			}
		}
	}
	w, ok := l.hits[key]
	if !ok || now.Sub(w.start) >= l.rate.Per {
		l.hits[key] = &window{start: now, n: 1}
		return true
	}
	if w.n >= l.rate.N {
		return false
	}
	w.n++
	return true
}
