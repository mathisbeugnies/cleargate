package api

import (
	"cleargate/pkg/auth"
	"cleargate/pkg/storage"
	"context"
	"encoding/json"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

// dummyHash is compared against when a login email is unknown, so the response
// time does not reveal whether the account exists.
var dummyHash = []byte("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy")

type AuthHandler struct {
	store *storage.Store
}

func NewAuthHandler(store *storage.Store) *AuthHandler {
	return &AuthHandler{store: store}
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token string `json:"token"`
	Role  string `json:"role"`
	Email string `json:"email"`
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid Request")
		return
	}

	user, err := h.store.GetUserByEmail(req.Email)
	if err != nil {
		// Spend comparable time so a missing account can't be told apart by timing.
		bcrypt.CompareHashAndPassword(dummyHash, []byte(req.Password))
		writeError(w, http.StatusUnauthorized, "invalid Credentials")
		return
	}

	// Verify Password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid Credentials")
		return
	}

	// Generate Token
	token, err := auth.GenerateToken(user.ID, user.Email, user.Role, user.OrganizationID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token Generation Failed")
		return
	}

	setSessionCookie(w, r, token)
	json.NewEncoder(w).Encode(LoginResponse{
		Token: token,
		Role:  user.Role,
		Email: user.Email,
	})
}

// Logout clears the session cookie.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	clearSessionCookie(w, r)
	w.WriteHeader(http.StatusNoContent)
}

// Me returns the current session's user, or 401. Used by the dashboard on load.
func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	claims, ok := UserFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "no session")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"email":  claims.Email,
		"role":   claims.Role,
		"org_id": claims.OrgID,
	})
}

// AuthMiddleware accepts a session from the Authorization bearer header or the
// httpOnly session cookie.
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := tokenFromRequest(r)
		if tokenString == "" {
			writeError(w, http.StatusUnauthorized, "missing session")
			return
		}

		claims, err := auth.ValidateToken(tokenString)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid session")
			return
		}

		ctx := context.WithValue(r.Context(), userContextKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
