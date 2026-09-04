package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTokenFromRequest(t *testing.T) {
	// Bearer header wins.
	r1 := httptest.NewRequest(http.MethodGet, "/", nil)
	r1.Header.Set("Authorization", "Bearer abc.def.ghi")
	if got := tokenFromRequest(r1); got != "abc.def.ghi" {
		t.Fatalf("bearer: got %q", got)
	}

	// Non-bearer Authorization -> empty.
	r2 := httptest.NewRequest(http.MethodGet, "/", nil)
	r2.Header.Set("Authorization", "Basic xxx")
	if got := tokenFromRequest(r2); got != "" {
		t.Fatalf("basic auth should yield no token, got %q", got)
	}

	// Falls back to the session cookie.
	r3 := httptest.NewRequest(http.MethodGet, "/", nil)
	r3.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "cookie.jwt.value"})
	if got := tokenFromRequest(r3); got != "cookie.jwt.value" {
		t.Fatalf("cookie: got %q", got)
	}
}

func TestSessionCookieFlags(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/login", nil) // no TLS

	setSessionCookie(rec, req, "the.jwt")
	c := rec.Result().Cookies()[0]
	if c.Name != SessionCookieName || c.Value != "the.jwt" {
		t.Fatalf("bad cookie: %+v", c)
	}
	if !c.HttpOnly {
		t.Error("session cookie must be HttpOnly")
	}
	if c.Secure {
		t.Error("Secure should be off for a plain-HTTP request")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Error("expected SameSite=Lax")
	}

	// Behind TLS termination.
	req.Header.Set("X-Forwarded-Proto", "https")
	rec2 := httptest.NewRecorder()
	setSessionCookie(rec2, req, "x")
	if !rec2.Result().Cookies()[0].Secure {
		t.Error("Secure should be set when X-Forwarded-Proto is https")
	}
}

func TestClearSessionCookie(t *testing.T) {
	rec := httptest.NewRecorder()
	clearSessionCookie(rec, httptest.NewRequest(http.MethodPost, "/auth/logout", nil))
	c := rec.Result().Cookies()[0]
	if c.MaxAge >= 0 {
		t.Fatalf("clear cookie should have MaxAge < 0, got %d", c.MaxAge)
	}
}

func TestRecoverMiddleware(t *testing.T) {
	h := Recover(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("want 500 after a panic, got %d", rec.Code)
	}
}
