package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"cleargate/pkg/auth"
)

func protected() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, ok := UserFromContext(r.Context()); !ok || c.OrgID == 0 {
			http.Error(w, "no claims", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
}

func TestAuthMiddleware(t *testing.T) {
	h := AuthMiddleware(protected())

	t.Run("missing header", func(t *testing.T) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/stats", nil))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("want 401, got %d", rec.Code)
		}
	})

	t.Run("garbage token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
		req.Header.Set("Authorization", "Bearer not-a-jwt")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("want 401, got %d", rec.Code)
		}
	})

	t.Run("valid token", func(t *testing.T) {
		tok, _ := auth.GenerateToken(1, "a@b.com", "org_admin", 9)
		req := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("want 200, got %d", rec.Code)
		}
	})
}

func TestRequireSuperAdmin(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	h := AuthMiddleware(RequireSuperAdmin(inner))

	orgTok, _ := auth.GenerateToken(1, "a@b.com", "org_admin", 9)
	req := httptest.NewRequest(http.MethodPost, "/api/admin/reload", nil)
	req.Header.Set("Authorization", "Bearer "+orgTok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("org_admin should be forbidden, got %d", rec.Code)
	}

	suTok, _ := auth.GenerateToken(2, "root@b.com", "super_admin", 9)
	req2 := httptest.NewRequest(http.MethodPost, "/api/admin/reload", nil)
	req2.Header.Set("Authorization", "Bearer "+suTok)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("super_admin should pass, got %d", rec2.Code)
	}
}
