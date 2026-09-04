package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthz(t *testing.T) {
	rec := httptest.NewRecorder()
	Healthz(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
}

func TestGuardMetrics(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })

	// No token: open.
	open := GuardMetrics("", inner)
	rec := httptest.NewRecorder()
	open.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("open metrics: want 200, got %d", rec.Code)
	}

	// Token set: reject without / accept with.
	guarded := GuardMetrics("s3cr3t", inner)

	r1 := httptest.NewRecorder()
	guarded.ServeHTTP(r1, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if r1.Code != http.StatusUnauthorized {
		t.Fatalf("no token: want 401, got %d", r1.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer s3cr3t")
	r2 := httptest.NewRecorder()
	guarded.ServeHTTP(r2, req)
	if r2.Code != http.StatusOK {
		t.Fatalf("valid token: want 200, got %d", r2.Code)
	}
}
