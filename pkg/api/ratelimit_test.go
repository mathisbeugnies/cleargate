package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimiterAllowsBurstThenBlocks(t *testing.T) {
	rl := newMemLimiter(3, time.Hour)

	for i := 0; i < 3; i++ {
		if !rl.allow("1.2.3.4") {
			t.Fatalf("request %d should be allowed within the burst", i+1)
		}
	}
	if rl.allow("1.2.3.4") {
		t.Fatal("4th request should be blocked once the burst is spent")
	}
}

func TestRateLimiterIsPerKey(t *testing.T) {
	rl := newMemLimiter(1, time.Hour)

	if !rl.allow("10.0.0.1") {
		t.Fatal("first IP should be allowed")
	}
	if !rl.allow("10.0.0.2") {
		t.Fatal("a different IP must not be affected by the first IP's bucket")
	}
	if rl.allow("10.0.0.1") {
		t.Fatal("first IP is now over its limit")
	}
}

func TestRateLimiterRefills(t *testing.T) {
	rl := newMemLimiter(1, 10*time.Millisecond)

	if !rl.allow("k") {
		t.Fatal("initial request should pass")
	}
	if rl.allow("k") {
		t.Fatal("immediate second request should be blocked")
	}
	time.Sleep(15 * time.Millisecond)
	if !rl.allow("k") {
		t.Fatal("request should pass again after the bucket refills")
	}
}

func TestRateLimitMiddlewareReturns429(t *testing.T) {
	var served int
	h := RateLimit(1, time.Hour, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served++
		w.WriteHeader(http.StatusOK)
	}))

	rec1 := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/signup", nil)
	req.RemoteAddr = "203.0.113.5:44321"
	h.ServeHTTP(rec1, req)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first call: want 200, got %d", rec1.Code)
	}

	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("second call: want 429, got %d", rec2.Code)
	}
	if rec2.Header().Get("Retry-After") == "" {
		t.Error("429 response should carry a Retry-After header")
	}
	if served != 1 {
		t.Fatalf("handler should have run exactly once, ran %d times", served)
	}
}

func TestClientIPPrefersForwardedFor(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:5555"
	req.Header.Set("X-Forwarded-For", "198.51.100.7, 10.0.0.1")

	if got := clientIP(req); got != "198.51.100.7" {
		t.Fatalf("want first X-Forwarded-For hop, got %q", got)
	}
}

func TestClientIPFallsBackToRemoteAddr(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.0.2.9:12345"

	if got := clientIP(req); got != "192.0.2.9" {
		t.Fatalf("want host from RemoteAddr, got %q", got)
	}
}
