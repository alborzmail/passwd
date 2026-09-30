package main

import (
	"strings"
	"sync"
	"time"
)

// limitHeld bounds the users remembered, so a flood of names cannot grow the map.
const limitHeld = 4096

// Limiter pauses a user after tries failed attempts within window.
type Limiter struct {
	tries  int
	window time.Duration

	mu     sync.Mutex
	failed map[string][]time.Time
}

func NewLimiter(tries int, window time.Duration) *Limiter {
	return &Limiter{tries: tries, window: window, failed: map[string][]time.Time{}}
}

func (l *Limiter) recent(user string, now time.Time) []time.Time {
	var out []time.Time
	for _, at := range l.failed[user] {
		if now.Sub(at) < l.window {
			out = append(out, at)
		}
	}
	return out
}

// Allow reports whether user may try a password now. While the map is full of live entries a
// user not in it waits too: dropping one would let its attempts start over.
func (l *Limiter) Allow(user string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	user = strings.ToLower(user)
	if _, held := l.failed[user]; !held && len(l.failed) >= limitHeld {
		for u := range l.failed {
			if len(l.recent(u, now)) == 0 {
				delete(l.failed, u)
			}
		}
		return len(l.failed) < limitHeld
	}
	return len(l.recent(user, now)) < l.tries
}

// Fail counts a failed attempt of a user Allow let through.
func (l *Limiter) Fail(user string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	user = strings.ToLower(user)
	if _, held := l.failed[user]; !held && len(l.failed) >= limitHeld {
		return
	}
	l.failed[user] = append(l.recent(user, now), now)
}
