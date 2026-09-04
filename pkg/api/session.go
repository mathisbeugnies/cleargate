package api

import (
	"net/http"
	"strings"
	"time"
)

// SessionCookieName is the httpOnly cookie the dashboard authenticates with.
const SessionCookieName = "cleargate_session"

const sessionTTL = 8 * time.Hour

// isHTTPS reports whether the original client request arrived over TLS, either
// directly or via a reverse proxy that set X-Forwarded-Proto.
func isHTTPS(r *http.Request) bool {
	return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
}

// setSessionCookie stores the JWT in an httpOnly, SameSite=Lax cookie.
func setSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(sessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
	})
}

// clearSessionCookie expires the session cookie.
func clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isHTTPS(r),
		SameSite: http.SameSiteLaxMode,
	})
}

// tokenFromRequest returns the session JWT from the Authorization header
// (API clients) or, failing that, the session cookie (dashboard).
func tokenFromRequest(r *http.Request) string {
	if h := r.Header.Get("Authorization"); h != "" {
		after, ok := strings.CutPrefix(h, "Bearer ")
		if !ok {
			return ""
		}
		return after
	}
	if c, err := r.Cookie(SessionCookieName); err == nil {
		return c.Value
	}
	return ""
}
