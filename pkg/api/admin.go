package api

import (
	"cleargate/pkg/cache"
	"cleargate/pkg/policy"
	"cleargate/pkg/storage"
	"cleargate/pkg/vector"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"strconv"
	"time"

	"github.com/rs/zerolog/log"
)

// AdminHandler manages administrative endpoints for the dashboard.
// It handles policy configuration, audit log retrieval, and system maintenance.
type AdminHandler struct {
	store      *storage.Store
	engine     *policy.Engine
	cache      *cache.Client
	guard      *vector.Guard
	reloadChan chan struct{}
}

// NewAdminHandler creates a new AdminHandler instance.
func NewAdminHandler(store *storage.Store, engine *policy.Engine, guard *vector.Guard, cacheClient *cache.Client, reloadChan chan struct{}) *AdminHandler {
	return &AdminHandler{store: store, engine: engine, guard: guard, cache: cacheClient, reloadChan: reloadChan}
}

// authenticate extracts OrgID from JWT Context
func (h *AdminHandler) authenticate(r *http.Request) (int, error) {
	claims, ok := UserFromContext(r.Context())
	if !ok {
		return 0, fmt.Errorf("no auth context")
	}
	return claims.OrgID, nil
}

// ServeAuditLogs handles retrieval and flushing of audit logs.
// GET:/api/admin/audit?limit=N&offset=N&q=... (Search & Filter)
// DELETE: /api/admin/audit (Flush old logs)
func (h *AdminHandler) ServeAuditLogs(w http.ResponseWriter, r *http.Request) {
	orgID, err := h.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	if r.Method == "DELETE" {
		count, err := h.store.DeleteOldAuditLogs(orgID, 90) // 90-day retention, scoped to this org
		if err != nil {
			log.Error().Err(err).Msg("Failed to flush audit logs")
			writeError(w, http.StatusInternalServerError, "dB Error")
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{"deleted": count})
		return
	}

	// Parse Query Params
	query := r.URL.Query()
	limit, _ := strconv.Atoi(query.Get("limit"))
	offset, _ := strconv.Atoi(query.Get("offset"))
	fromTime, _ := time.Parse(time.RFC3339, query.Get("from"))
	toTime, _ := time.Parse(time.RFC3339, query.Get("to"))

	filter := storage.AuditLogFilter{
		UserID:    query.Get("user"),
		Verdict:   query.Get("verdict"),
		RiskLevel: query.Get("risk"),
		Search:    query.Get("q"),
		From:      fromTime,
		To:        toTime,
		Limit:     limit,
		Offset:    offset,
	}

	logs, err := h.store.GetAuditLogs(orgID, filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "dB Error")
		return
	}

	format := r.URL.Query().Get("format")
	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment;filename=audit_logs.csv")

		writer := csv.NewWriter(w)
		writer.Write([]string{"Timestamp", "RequestID", "User", "PromptHash", "Verdict", "RiskScore", "Threats", "Similarity"})

		for _, l := range logs {
			writer.Write([]string{
				l.Timestamp.String(),
				l.RequestID,
				l.UserID,
				l.PromptHash,
				l.Verdict,
				strconv.Itoa(l.RiskScore),
				l.ThreatDetails,
				fmt.Sprintf("%f", l.SimilarityScore),
			})
		}
		writer.Flush()
	} else {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(logs)
	}
}

// SystemStats aggregates real-time metrics for the dashboard.
type SystemStats struct {
	MemUsageMB   uint64         `json:"mem_usage_mb"`
	NumGoroutine int            `json:"num_goroutine"`
	VectorCount  uint64         `json:"vector_count"`
	StorageStats *storage.Stats `json:"storage_stats"`
}

// ServeStats returns system health and usage statistics.
func (h *AdminHandler) ServeStats(w http.ResponseWriter, r *http.Request) {
	orgID, err := h.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	dbStats, err := h.store.GetStats(orgID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "dB Error")
		return
	}

	// Runtime Stats
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// Vector Stats
	vecCount, _ := h.guard.Client().GetCollectionInfo(vector.CollectionName)

	fullStats := SystemStats{
		MemUsageMB:   m.Alloc / 1024 / 1024,
		NumGoroutine: runtime.NumGoroutine(),
		VectorCount:  vecCount,
		StorageStats: dbStats,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(fullStats)
}

// ServeReload triggers a graceful reload of the system configuration.
func (h *AdminHandler) ServeReload(w http.ResponseWriter, r *http.Request) {
	_, err := h.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	if r.Method != "POST" {
		writeError(w, http.StatusMethodNotAllowed, "method Not Allowed")
		return
	}

	// Trigger Reload via Channel
	select {
	case h.reloadChan <- struct{}{}:
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "reloading"})
	default:
		// Prevent blocking if already reloading
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"status": "busy", "error": "reload in progress"})
	}
}

// ServeConfig handles reading and updating the organization's security policy.
func (h *AdminHandler) ServeConfig(w http.ResponseWriter, r *http.Request) {
	orgID, err := h.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	if r.Method == "GET" {
		configStr, _ := h.store.GetPolicyByOrgID(orgID)
		cfg := h.engine.ParseConfig(configStr)
		json.NewEncoder(w).Encode(cfg)
		return
	}

	if r.Method == "POST" {
		var newConfig policy.GlobalConfig
		if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON")
			return
		}

		// Serialize to JSON
		bytes, _ := json.Marshal(newConfig)
		if err := h.store.UpdatePolicy(orgID, string(bytes)); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to update policy")
			return
		}

		// Invalidate Cache for this Org
		if h.cache != nil {
			h.cache.InvalidateOrg(r.Context(), orgID)
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(newConfig)
		return
	}

	writeError(w, http.StatusMethodNotAllowed, "method Not Allowed")
}

// ServeKeys handles the rotation of RSA keys for data encryption.
func (h *AdminHandler) ServeKeys(w http.ResponseWriter, r *http.Request) {
	orgID, err := h.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	if r.Method == "POST" {
		var req struct {
			PublicKey string `json:"public_key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON")
			return
		}

		if err := h.store.UpdateOrganizationKey(orgID, req.PublicKey); err != nil {
			log.Error().Err(err).Msg("Failed to update public key")
			writeError(w, http.StatusInternalServerError, "dB Error")
			return
		}

		w.WriteHeader(http.StatusOK)
		return
	}

	writeError(w, http.StatusMethodNotAllowed, "method Not Allowed (Only POST supported for now)")
}

// ServeIntegrityCheck verifies the hash chain of audit logs to detect tampering.
func (h *AdminHandler) ServeIntegrityCheck(w http.ResponseWriter, r *http.Request) {
	orgID, err := h.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	report, err := h.store.VerifyIntegrity(orgID)
	if err != nil {
		log.Error().Err(err).Msg("Integrity check failed")
		writeError(w, http.StatusInternalServerError, "internal Error during verification")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(report)
}

// ServeFeedback allows admins to whitelist a blocked prompt as a false positive (Exception).
func (h *AdminHandler) ServeFeedback(w http.ResponseWriter, r *http.Request) {
	_, err := h.authenticate(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	if r.Method != "POST" {
		writeError(w, http.StatusMethodNotAllowed, "method Not Allowed")
		return
	}

	var req struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if req.Text == "" {
		writeError(w, http.StatusBadRequest, "empty text")
		return
	}

	if err := h.guard.AddException(req.Text); err != nil {
		log.Error().Err(err).Msg("Failed to add exception")
		writeError(w, http.StatusInternalServerError, "internal Error")
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "exception_added"})
}
