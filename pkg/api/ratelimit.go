package api

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"cleargate/pkg/cache"
)

// limiter decides whether a request from a given key (client IP) may proceed.
type limiter interface {
	allow(key string) bool
}

// memLimiter is an in-memory token bucket keyed by client IP. Used when no
// shared store is configured; it is per-process, so it does not enforce a
// global limit across multiple instances.
type memLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	rate     float64
	capacity float64
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newMemLimiter(burst int, per time.Duration) *memLimiter {
	rl := &memLimiter{
		buckets:  make(map[string]*bucket),
		capacity: float64(burst),
		rate:     float64(burst) / per.Seconds(),
	}
	go rl.sweep()
	return rl
}

func (rl *memLimiter) allow(key string) bool {
	now := time.Now()

	rl.mu.Lock()
	defer rl.mu.Unlock()

	b, ok := rl.buckets[key]
	if !ok {
		rl.buckets[key] = &bucket{tokens: rl.capacity - 1, last: now}
		return true
	}

	b.tokens += now.Sub(b.last).Seconds() * rl.rate
	if b.tokens > rl.capacity {
		b.tokens = rl.capacity
	}
	b.last = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (rl *memLimiter) sweep() {
	for range time.Tick(10 * time.Minute) {
		now := time.Now()
		rl.mu.Lock()
		for key, b := range rl.buckets {
			if now.Sub(b.last) > 30*time.Minute {
				delete(rl.buckets, key)
			}
		}
		rl.mu.Unlock()
	}
}

// redisLimiter is a fixed-window counter in Redis, shared across instances.
// It fails open: if Redis is unavailable the request is allowed.
type redisLimiter struct {
	cache  *cache.Client
	name   string
	burst  int
	window time.Duration
}

func newRedisLimiter(c *cache.Client, name string, burst int, per time.Duration) *redisLimiter {
	return &redisLimiter{cache: c, name: name, burst: burst, window: per}
}

func (rl *redisLimiter) allow(key string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	slot := time.Now().Unix() / int64(rl.window.Seconds())
	redisKey := fmt.Sprintf("ratelimit:%s:%s:%d", rl.name, key, slot)

	n := rl.cache.Incr(ctx, redisKey, rl.window+time.Second)
	if n == 0 { // Redis error -> fail open
		return true
	}
	return n <= int64(rl.burst)
}

// clientIP honours one X-Forwarded-For hop, assuming a single trusted proxy.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		first, _, _ := strings.Cut(xff, ",")
		if ip := strings.TrimSpace(first); ip != "" {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func rateLimitMiddleware(l limiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !l.allow(clientIP(r)) {
			w.Header().Set("Retry-After", "60")
			writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RateLimit enforces a per-IP limit using an in-memory bucket.
func RateLimit(burst int, per time.Duration, next http.Handler) http.Handler {
	return rateLimitMiddleware(newMemLimiter(burst, per), next)
}

// RateLimitShared enforces a per-IP limit backed by Redis when available (so it
// holds across multiple instances), falling back to an in-memory bucket.
func RateLimitShared(c *cache.Client, name string, burst int, per time.Duration, next http.Handler) http.Handler {
	var l limiter
	if c != nil {
		l = newRedisLimiter(c, name, burst, per)
	} else {
		l = newMemLimiter(burst, per)
	}
	return rateLimitMiddleware(l, next)
}
