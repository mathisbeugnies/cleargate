package api

import (
	"cleargate/pkg/storage"
	"encoding/json"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type PublicHandler struct {
	store *storage.Store
}

func NewPublicHandler(store *storage.Store) *PublicHandler {
	return &PublicHandler{store: store}
}

func (h *PublicHandler) GetInvitation(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		writeError(w, http.StatusBadRequest, "missing token")
		return
	}

	inv, err := h.store.GetInvitationByToken(token)
	if err != nil {
		writeError(w, http.StatusNotFound, "invalid token")
		return
	}

	if inv.Used {
		writeError(w, http.StatusConflict, "invitation already used")
		return
	}

	if time.Now().After(inv.ExpiresAt) {
		writeError(w, http.StatusGone, "invitation expired")
		return
	}

	// Returns minimal info for display
	json.NewEncoder(w).Encode(map[string]string{
		"email": inv.Email,
		"role":  inv.Role,
	})
}

type SetupRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

func (h *PublicHandler) CompleteSetup(w http.ResponseWriter, r *http.Request) {
	var req SetupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid Request")
		return
	}

	inv, err := h.store.GetInvitationByToken(req.Token)
	if err != nil || inv.Used || time.Now().After(inv.ExpiresAt) {
		writeError(w, http.StatusBadRequest, "invalid or expired invitation")
		return
	}

	// Hash Password
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "error hashing password")
		return
	}

	// Create User
	if err := h.store.CreateUser(inv.Email, string(hash), inv.Role, inv.OrganizationID); err != nil {
		writeError(w, http.StatusConflict, "failed to create user (maybe email exists?)")
		return
	}

	// Mark Used
	h.store.MarkInvitationUsed(inv.ID)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Account created successfully"})
}
