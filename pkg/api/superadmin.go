package api

import (
	"cleargate/pkg/mail"
	"cleargate/pkg/storage"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

type SuperAdminHandler struct {
	store *storage.Store
	mail  *mail.Service
}

func NewSuperAdminHandler(store *storage.Store, mail *mail.Service) *SuperAdminHandler {
	return &SuperAdminHandler{store: store, mail: mail}
}

// Middleware to ensure user is super_admin
func RequireSuperAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := UserFromContext(r.Context())
		if !ok || claims.Role != "super_admin" {
			writeError(w, http.StatusForbidden, "forbidden: Super Admin only")
			return
		}
		next.ServeHTTP(w, r)
	})
}

type CreateOrgRequest struct {
	Name       string `json:"name"`
	AdminEmail string `json:"admin_email"`
}

func (h *SuperAdminHandler) CreateOrganization(w http.ResponseWriter, r *http.Request) {
	var req CreateOrgRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid Request")
		return
	}

	// Generate a secure API Key
	apiKey := generateRandomKey()

	orgID, err := h.store.CreateOrganization(req.Name, apiKey)
	if err != nil {
		log.Error().Err(err).Msg("CreateOrganization Error")
		writeError(w, http.StatusInternalServerError, "failed to create organization")
		return
	}

	// Apply default security policy for the new organization
	defaultConfig := `{"email_redaction":true,"phone_redaction":true,"api_key_detection":true,"source_code_dlp":true,"prompt_injection":true,"vector_guard":true}`
	h.store.UpdatePolicy(orgID, defaultConfig)

	// Generate invitation token
	token := uuid.New().String()
	inv := storage.Invitation{
		Token:          token,
		Email:          req.AdminEmail,
		Role:           "org_admin",
		OrganizationID: orgID,
		ExpiresAt:      time.Now().Add(48 * time.Hour),
	}

	if err := h.store.CreateInvitation(inv); err != nil {
		log.Error().Err(err).Msg("CreateInvitation Error")
		writeError(w, http.StatusInternalServerError, "failed to create invitation")
		return
	}

	// Send invitation via email service
	inviteLink := fmt.Sprintf("%s/setup?token=%s", strings.TrimRight(DashboardURL, "/"), token)
	if err := h.mail.SendInvitation(req.AdminEmail, inviteLink, req.Name); err != nil {
		log.Error().Err(err).Msg("SendInvitation Error")
		// We don't fail the request, but we log the error. Admin can resend invite later (feature todo).
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"message":     "Organization created and invitation sent",
		"invite_link": inviteLink, // Return link for demo convenience
		"api_key":     apiKey,
	})
}

func (h *SuperAdminHandler) ListOrganizations(w http.ResponseWriter, r *http.Request) {
	orgs, err := h.store.GetOrganizations()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "dB Error")
		return
	}
	json.NewEncoder(w).Encode(orgs)
}

func generateRandomKey() string {
	bytes := make([]byte, 24)
	if _, err := rand.Read(bytes); err != nil {
		// crypto/rand failing is unrecoverable for a security product.
		log.Fatal().Err(err).Msg("Failed to generate API key")
	}
	return "sk-" + hex.EncodeToString(bytes)
}
