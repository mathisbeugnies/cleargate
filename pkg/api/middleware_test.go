package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
}

func TestCorsAllowListRejectsUnknownOrigin(t *testing.T) {
	old := AllowedOrigins
	AllowedOrigins = "https://app.example.com"
	defer func() { AllowedOrigins = old }()

	h := CorsMiddleware(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	req.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("unknown origin should not be allowed, got %q", got)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	req2.Header.Set("Origin", "https://app.example.com")
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if got := rec2.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Fatalf("allowed origin not echoed, got %q", got)
	}
}

func TestSecurityHeadersSet(t *testing.T) {
	h := SecurityHeaders(okHandler())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	for _, k := range []string{"X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy", "Referrer-Policy"} {
		if rec.Header().Get(k) == "" {
			t.Errorf("missing security header %s", k)
		}
	}
}
