package scan

import (
	"context"
	"sync"
	"time"
)

// limiter is a simple token bucket: it issues one token every interval.
// wait blocks until a token is available or ctx is canceled.
type limiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

func newLimiter(rps float64) *limiter {
	if rps <= 0 {
		return nil
	}
	return &limiter{
		interval: time.Duration(float64(time.Second) / rps),
		next:     time.Now(),
	}
}

func (l *limiter) wait(ctx context.Context) {
	if l == nil {
		return
	}
	l.mu.Lock()
	now := time.Now()
	if now.After(l.next) {
		l.next = now
	}
	wait := l.next.Sub(now)
	l.next = l.next.Add(l.interval)
	l.mu.Unlock()

	if wait <= 0 {
		return
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}
