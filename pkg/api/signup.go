package api

import (
	"cleargate/pkg/auth"
	"cleargate/pkg/storage"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
)

type SignupHandler struct {
	store *storage.Store
}

func NewSignupHandler(store *storage.Store) *SignupHandler {
	return &SignupHandler{store: store}
}

type SignupRequest struct {
	OrgName  string `json:"org_name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type SignupResponse struct {
	Token  string `json:"token"`
	Role   string `json:"role"`
	Email  string `json:"email"`
	ApiKey string `json:"api_key"`
	OrgID  int    `json:"org_id"`
}

// Policy new self-serve orgs start with. Vector Guard is off because it needs
// a seeded Qdrant collection the org doesn't have yet.
const defaultSelfServePolicy = `{"email_redaction":true,"phone_redaction":true,"api_key_detection":true,"source_code_dlp":true,"prompt_injection":true,"vector_guard":false}`

// reservedLocalPart blocks signups on addresses commonly used for privileged or
// automated accounts, so self-serve users can't squat them.
func reservedLocalPart(email string) bool {
	local, _, ok := strings.Cut(email, "@")
	if !ok {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(local)) {
	case "admin", "administrator", "root", "superadmin", "super-admin", "postmaster", "abuse", "security", "no-reply", "noreply":
		return true
	}
	return false
}

// Signup creates an organization, its API key and a first org_admin user in one
// request and returns a session token. No approval or email confirmation step.
func (h *SignupHandler) Signup(w http.ResponseWriter, r *http.Request) {
	var req SignupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid Request")
		return
	}

	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	req.OrgName = strings.TrimSpace(req.OrgName)

	if req.Email == "" || !strings.Contains(req.Email, "@") {
		writeError(w, http.StatusBadRequest, "a valid email is required")
		return
	}
	if len(req.Password) < 8 {
		writeError(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}
	if req.OrgName == "" {
		req.OrgName = req.Email
	}

	if reservedLocalPart(req.Email) {
		writeError(w, http.StatusForbidden, "this email address is reserved")
		return
	}

	if _, err := h.store.GetUserByEmail(req.Email); err == nil {
		writeError(w, http.StatusConflict, "an account with this email already exists")
		return
	}

	// Hash before writing anything, so a hashing failure can't orphan an org.
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Error().Err(err).Msg("Signup: password hashing failed")
		writeError(w, http.StatusInternalServerError, "failed to secure password")
		return
	}

	apiKey := generateRandomKey()
	orgID, err := h.store.CreateOrganization(req.OrgName, apiKey)
	if err != nil {
		log.Error().Err(err).Msg("Signup: CreateOrganization failed")
		writeError(w, http.StatusInternalServerError, "failed to create organization")
		return
	}

	if err := h.store.UpdatePolicy(orgID, defaultSelfServePolicy); err != nil {
		log.Error().Err(err).Msg("Signup: UpdatePolicy failed")
	}

	if err := h.store.CreateUser(req.Email, string(hash), "org_admin", orgID); err != nil {
		log.Error().Err(err).Msg("Signup: CreateUser failed")
		writeError(w, http.StatusInternalServerError, "failed to create user")
		return
	}

	user, err := h.store.GetUserByEmail(req.Email)
	if err != nil {
		log.Error().Err(err).Msg("Signup: GetUserByEmail failed right after creation")
		writeError(w, http.StatusInternalServerError, "account created but automatic login failed, please sign in manually")
		return
	}

	token, err := auth.GenerateToken(user.ID, user.Email, user.Role, user.OrganizationID)
	if err != nil {
		log.Error().Err(err).Msg("Signup: token generation failed")
		writeError(w, http.StatusInternalServerError, "token Generation Failed")
		return
	}

	setSessionCookie(w, r, token)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(SignupResponse{
		Token:  token,
		Role:   user.Role,
		Email:  user.Email,
		ApiKey: apiKey,
		OrgID:  orgID,
	})
}
