package proxy

import (
	"bytes"
	"cleargate/pkg/cache"
	"cleargate/pkg/crypto"
	"cleargate/pkg/metrics"
	"cleargate/pkg/policy"
	"cleargate/pkg/provider"
	"cleargate/pkg/sanitizer"
	"cleargate/pkg/security"
	"cleargate/pkg/storage"
	"cleargate/pkg/vector"
	"cleargate/pkg/watermark"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

const (
	HeaderProvider = "X-ClearGate-Provider"
	HeaderUser     = "X-ClearGate-User"
	HeaderKey      = "X-ClearGate-Key" // New Auth Header
)

// ProxyHandler is the main HTTP handler that orchestrates the request pipeline.
// It coordinates authentication, security checks, logging, and provider forwarding.
type ProxyHandler struct {
	providers map[string]provider.Provider
	store     *storage.Store
	policy    *policy.Engine
	guard     *vector.Guard
	injector  *security.IntentClassifier
	leak      *security.LeakDetector
	sanitizer *sanitizer.Sanitizer
	anomaly   *security.AnomalyDetector
	cache     *cache.Client
	watermark *watermark.Encoder
}

// NewProxyHandler initializes all dependencies and returns a new ProxyHandler instance.
func NewProxyHandler(store *storage.Store, policyEngine *policy.Engine, guard *vector.Guard, injector *security.IntentClassifier, leak *security.LeakDetector, cacheClient *cache.Client, sanitizerService *sanitizer.Sanitizer, anomaly *security.AnomalyDetector) *ProxyHandler {
	return &ProxyHandler{
		providers: map[string]provider.Provider{
			"openai":    provider.NewOpenAIProvider(),
			"mistral":   provider.NewMistralProvider(),
			"anthropic": provider.NewAnthropicProvider(),
		},
		store:     store,
		policy:    policyEngine,
		guard:     guard,
		injector:  injector,
		leak:      leak,
		sanitizer: sanitizerService,
		anomaly:   anomaly,
		cache:     cacheClient,
		watermark: watermark.NewEncoder(),
	}
}

// MaxBodyBytes caps the size of a proxied request body. Override with
// MAX_BODY_BYTES. Default 10 MiB.
var MaxBodyBytes int64 = 10 << 20

// ServeHTTP handles incoming HTTP requests, orchestrating the full security pipeline.
// Steps: Auth, Anomaly Check, Normalization, Caching, Signal Gathering, Policy Decision, Enforcement, Logging.
func (h *ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)

	// Authenticate the organization using the API Key
	apiKey := r.Header.Get(HeaderKey)
	if apiKey == "" {
		writeErr(w, http.StatusUnauthorized, "missing API Key")
		return
	}

	org, err := h.store.GetOrganizationByKey(apiKey)
	if err != nil {
		log.Warn().Str("key_prefix", keyPrefix(apiKey)).Msg("Invalid API Key attempt")
		writeErr(w, http.StatusUnauthorized, "invalid API Key")
		return
	}

	// User extraction moved below with Config parsing

	// User ID extraction happens later now

	// Load the policy configuration for the organization
	policyStr, _ := h.store.GetPolicyByOrgID(org.ID)
	orgConfig := h.policy.ParseConfig(policyStr)

	userID := r.Header.Get(HeaderUser)
	if userID == "" {
		userID = "anonymous"
	}

	// 0. Anomaly Access Check (Is User Blocked?)
	if orgConfig.AnomalyDetection {
		if allowed, reason := h.anomaly.CheckAccess(r.Context(), userID); !allowed {
			log.Warn().Str("user_id", userID).Msg("Blocked User Attempt")
			writeErr(w, http.StatusTooManyRequests, "access denied: "+reason)
			return
		}
	}

	// ... Provider selection ...
	providerName := r.Header.Get(HeaderProvider)
	if providerName == "" {
		providerName = "openai" // Default
	}
	p, ok := h.providers[strings.ToLower(providerName)]
	if !ok {
		log.Error().Str("provider", providerName).Msg("Unknown provider requested")
		writeErr(w, http.StatusBadRequest, "unknown provider: "+providerName)
		return
	}

	// Read Body
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeErr(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		writeErr(w, http.StatusBadRequest, "failed to read body")
		return
	}
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	originalBody := string(bodyBytes)

	// 1. Normalization & Obfuscation Check
	normalizedBody, isObfuscated := security.NormalizePrompt(originalBody)
	baseRiskScore := 0
	if isObfuscated {
		log.Warn().Str("user_id", userID).Msg("Obfuscation Detected in Prompt")
		baseRiskScore = 30 // Penalize obfuscation
	}

	// Audit Trail Init
	requestID := uuid.New().String()
	hash := sha256.Sum256([]byte(normalizedBody)) // Hash key based on NORMALIZED content
	promptHash := hex.EncodeToString(hash[:])

	log.Info().Str("request_id", requestID).Int("org_id", org.ID).Msg("Request received")

	// 0.5 Cache Check (Fast-Path)
	cacheKey := fmt.Sprintf("org:%d:%s", org.ID, promptHash)
	if h.cache != nil {
		verdict := h.cache.GetVerdict(r.Context(), cacheKey)
		if verdict == "SAFE" {
			w.Header().Set("X-ClearGate-Cache", "HIT")
			log.Info().Str("request_id", requestID).Msg("Cache HIT (SAFE) - Fast Path")
			// Forward to Provider
			h.anomaly.TrackUsage(r.Context(), userID, len(normalizedBody)/4)
			h.forwardToProvider(w, r, p, normalizedBody, orgConfig, org.ID, requestID, userID, promptHash)
			return
		} else if verdict == "BLOCK" {
			w.Header().Set("X-ClearGate-Cache", "HIT")
			writeErr(w, http.StatusForbidden, "request blocked (Cached Decision)")
			return
		}
		w.Header().Set("X-ClearGate-Cache", "MISS")
	}

	// 3. Security Checks - GATHER SIGNALS PHASE
	riskCtx := policy.RiskContext{
		Obfuscated: isObfuscated,
	}

	// 3.1 Prompt Leak
	if orgConfig.PromptLeaking {
		if leaked, reason := h.leak.Detect(normalizedBody); leaked {
			riskCtx.LeakDetected = true
			riskCtx.LeakReason = reason
		}
	}

	// 3.2 Prompt Injection
	if orgConfig.PromptInjection {
		// Pass 0.0 threshold to get raw score, we decide later
		if blocked, score, reason := h.injector.Detect(normalizedBody, 0.0); blocked || score > 0 {
			riskCtx.InjectionScore = score
			riskCtx.InjectionReason = reason
		}
	}

	// 3.3 Vector Guard
	if orgConfig.VectorGuard {
		// A. Forbidden Sector Check
		if blocked, score, reason := h.guard.IsBlocked(normalizedBody, org.ID); blocked || score > 0 {
			riskCtx.VectorScore = score
			riskCtx.VectorReason = reason
		}

		// B. Domain Verification (Positive Security)
		if isAnomaly, _ := h.guard.IsOutOfDomain(normalizedBody); isAnomaly {
			riskCtx.OutOfDomain = true
			log.Warn().Str("req_id", requestID).Msg("Vector Guard: Out-of-Domain Anomaly Detected")
		}
	}

	// 3.4 Sanitizer (PII Stats)
	// We run sanitize to get stats, but we only USE the body if verdict is MODIFY/PASS
	scanRes := h.sanitizer.Sanitize(normalizedBody, &sanitizer.Config{
		RedactEmails:     orgConfig.EmailRedaction,
		RedactPhones:     orgConfig.PhoneRedaction,
		RedactAPIKeys:    orgConfig.ApiKeyProtection,
		RedactSourceCode: orgConfig.SourceCodeDLP,
		EntropyScanner:   orgConfig.EntropyScanner,
		NerEnabled:       orgConfig.NerEnabled,
		MedicalCheck:     orgConfig.MedicalCheck,
	})

	// Extract Stats from Scan Result (Need detailed counts)
	// Currently ScanResult has piiCount (private). We might need to approximate or assume
	// based on mapped items?
	// Ah, ScanResult.Mapping contains all redactions.
	// We need to know specific Entity Types to fill HasPerson/HasMedical.
	// Sanitizer needs to return metadata. For now, we will infer from Mapping keys.
	riskCtx.PIICount = len(scanRes.Mapping)
	for k := range scanRes.Mapping {
		if strings.Contains(k, "PERSON") {
			riskCtx.HasPerson = true
		}
		if strings.Contains(k, "MEDICAL") || strings.Contains(k, "HEALTH") {
			riskCtx.HasMedical = true
		}
	}

	// 4. POLICY DECISION PHASE
	verdict := h.policy.AnalyzeRisk(riskCtx, orgConfig)

	// 5. ENFORCEMENT PHASE
	finalBody := normalizedBody
	totalRisk := verdict.Score + baseRiskScore

	if verdict.Action == "BLOCK" {
		log.Warn().Str("request_id", requestID).Int("risk_score", totalRisk).Str("reason", verdict.Reason).Msg("Blocked by Contextual Policy")
		h.logAndCache(r.Context(), cacheKey, "BLOCK", requestID, startTime, userID, p.Name(), promptHash, totalRisk, verdict.Reason, org.ID, "")
		h.anomaly.TrackRisk(r.Context(), userID, totalRisk)
		writeErr(w, http.StatusForbidden, "request blocked by security policy: "+verdict.Reason)
		return
	} else if verdict.Action == "MODIFY" {
		log.Info().Str("request_id", requestID).Msg("Request Modified (Sanitized) by Policy")
		finalBody = scanRes.SanitizedBody
		// We proceed with the sanitized body
	}

	// Vault Storage (If enabled and data found)
	useVault := orgConfig.TokenVault
	if useVault && len(scanRes.Mapping) > 0 {
		// Store Mapping in Redis (30 mins TTL)
		h.cache.SetVault(r.Context(), requestID, scanRes.Mapping, 30*time.Minute)
		log.Info().Str("request_id", requestID).Int("items", len(scanRes.Mapping)).Msg("Vault: Stored Detokenization Map")
	}

	// Encrypt Intercepted Data
	details := ""
	if len(scanRes.Mapping) > 0 {
		encryptedMapping := make(map[string]string)
		for k, v := range scanRes.Mapping {
			if org.PublicKey != "" {
				enc, err := crypto.EncryptRSA(v, org.PublicKey)
				if err == nil {
					encryptedMapping[k] = "RSA:" + enc
				} else {
					encryptedMapping[k] = "REDACTED_ENCRYPTION_FAILED"
				}
			} else {
				// If Vault is used, we might log the TOKEN key, but value is redacted
				encryptedMapping[k] = "REDACTED_NO_KEY"
			}
		}

		// Serialize for Audit Log
		if jsonBytes, err := json.Marshal(encryptedMapping); err == nil {
			details = string(jsonBytes)
		}
	}

	// Encrypt Original Prompt for Feedback Loop
	encryptedOriginalBody := ""
	if org.PublicKey != "" {
		if enc, err := crypto.EncryptRSA(normalizedBody, org.PublicKey); err == nil {
			encryptedOriginalBody = "RSA:" + enc
		}
	}

	// Log Request
	h.logAndCache(r.Context(), cacheKey, verdict.Action, requestID, startTime, userID, p.Name(), promptHash, totalRisk, details, org.ID, encryptedOriginalBody)

	// Anomaly Track Usage
	if orgConfig.AnomalyDetection {
		h.anomaly.TrackUsage(r.Context(), userID, len(finalBody)/4)
	}

	// 6. Forward to LLM
	// (Note: forwardToProvider needs to know if it should rehydrate.
	// Or we do rehydration inside forwardToProvider or after?
	// forwardToProvider writes to ResponseWriter directly.
	// We need to Intercept response body in forwardToProvider to rehydrate.)
	h.forwardToProvider(w, r, p, finalBody, orgConfig, org.ID, requestID, userID, promptHash)
}

// wantsStream reports whether the request JSON asks for a streamed response.
func wantsStream(body string) bool {
	compact := strings.NewReplacer(" ", "", "\t", "", "\n", "").Replace(body)
	return strings.Contains(compact, `"stream":true`)
}

// streamResponse relays an upstream response to the client without buffering,
// flushing each chunk so SSE tokens arrive live.
func (h *ProxyHandler) streamResponse(w http.ResponseWriter, resp *http.Response, reqID string) {
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.Header().Del("Content-Length")

	// Clear the server write deadline so a long stream isn't cut off.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})

	w.WriteHeader(resp.StatusCode)
	flusher, canFlush := w.(http.Flusher)

	buf := make([]byte, 8<<10)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			if canFlush {
				flusher.Flush()
			}
		}
		if err != nil {
			if err != io.EOF {
				log.Warn().Err(err).Str("request_id", reqID).Msg("Stream read error")
			}
			return
		}
	}
}

// writeErr sends a JSON error body: {"error": "..."}.
func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// keyPrefix returns a short, non-sensitive fragment of an API key for logging.
func keyPrefix(key string) string {
	if len(key) <= 8 {
		return "***"
	}
	return key[:8] + "..."
}

// logAndCache logs the request metadata to the database and caches the decision in Redis.
func (h *ProxyHandler) logAndCache(ctx context.Context, key, verdict, reqID string, start time.Time, user, provider, hash string, risk int, details string, orgID int, encryptedPrompt string) {
	elapsed := time.Since(start)
	latency := elapsed.Milliseconds()
	metrics.ObserveRequest(verdict, elapsed.Seconds())

	// Log to DB
	h.store.LogRequest(storage.RequestMetadata{
		RequestID:       reqID,
		Timestamp:       start,
		UserID:          user,
		Provider:        provider,
		PromptHash:      hash,
		Verdict:         verdict,
		RiskScore:       risk,
		ThreatDetails:   details,
		OrganizationID:  orgID,
		PromptEncrypted: encryptedPrompt,
		Latency:         latency,
	})

	// Cache Result (1 Hour)
	if h.cache != nil {
		h.cache.SetVerdict(ctx, key, verdict, 3600*time.Second)
	}
}

func (h *ProxyHandler) forwardToProvider(w http.ResponseWriter, r *http.Request, p provider.Provider, body string, config policy.GlobalConfig, orgID int, reqID, userID, promptHash string) {
	// Reconstruct Request Body
	r.Body = io.NopCloser(strings.NewReader(body))
	r.ContentLength = int64(len(body))

	resp, err := p.SendRequest(r)
	if err != nil {
		log.Error().Err(err).Msg("Provider request failed")
		metrics.ObserveUpstreamError()
		writeErr(w, http.StatusBadGateway, "provider request failed")
		return
	}
	defer resp.Body.Close()

	// Streaming (SSE) responses are relayed chunk by chunk. The prompt was
	// already sanitized and logged before we got here; output-side scanning
	// is not applied to a live stream.
	if wantsStream(body) || strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		h.streamResponse(w, resp, reqID)
		return
	}

	// Buffer the response so it can be scanned. Cap it so a hostile or broken
	// upstream can't exhaust memory.
	respBodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes+1))
	if err != nil {
		writeErr(w, http.StatusBadGateway, "failed to read provider response")
		return
	}
	if int64(len(respBodyBytes)) > MaxBodyBytes {
		writeErr(w, http.StatusBadGateway, "provider response too large")
		return
	}
	respBody := string(respBodyBytes)

	// OUTPUT GUARD & VAULT REHYDRATION

	// A. Vault Rehydration (Pre-Output Guard? Or Post?
	// Usually Post-Output Scan to ensure we verify the clean text?
	// Or Pre?
	// If LLM says "Hello [PERSON_UUID]", we want user to see "Hello Jean".
	// But Output Guard checks for forbidden topics. If topic is forbidden, we block.
	// If we rehydrate first, we might leak data if we block? No, blocking prevents sending.
	// Let's rehydrate at the very end before writing.

	if config.OutputControl {
		// 1. Vector Guard on Output
		if config.VectorGuard {
			if blocked, score, reason := h.guard.IsBlocked(respBody, orgID); blocked {
				log.Warn().Str("request_id", reqID).Msg("Blocked Output by Vector Guard")
				h.logAndCache(r.Context(), "N/A", "BLOCK", reqID, time.Now(), userID, p.Name(), promptHash, int(score*100), "AI_FORBIDDEN_TOPIC: "+reason, orgID, "")
				writeErr(w, http.StatusForbidden, "response blocked: AI generated forbidden content")
				return
			}
		}

		// 2. Sanitizer on Output
		scanRes := h.sanitizer.Sanitize(respBody, &sanitizer.Config{
			RedactEmails:     config.EmailRedaction,
			RedactPhones:     config.PhoneRedaction,
			RedactAPIKeys:    config.ApiKeyProtection,
			RedactSourceCode: config.SourceCodeDLP,
			EntropyScanner:   config.EntropyScanner,
			NerEnabled:       config.NerEnabled,
			MedicalCheck:     config.MedicalCheck,
			// Do NOT use Vault for output sanitization usually, or maybe yes?
			// UseVault: config.TokenVault? Only if we want to Tokenize NEW data generated by AI.
			// But here we want to DETOKENIZE the request data.
			UseVault: false,
		})

		if scanRes.SanitizedBody != respBody {
			log.Warn().Str("request_id", reqID).Msg("Sanitized AI Output (Leak Detected)")
			h.logAndCache(r.Context(), "N/A", "MODIFY", reqID, time.Now(), userID, p.Name(), promptHash, 80, fmt.Sprintf("AI_GENERATED_LEAK: Redacted %d items", len(scanRes.Mapping)), orgID, "")
			respBody = scanRes.SanitizedBody
			// Update headers for new length
			resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(respBody)))
		}
	}

	// B. Vault Rehydration (Final Step)
	if config.TokenVault && h.cache != nil {
		// Fetch Map
		vaultMap := h.cache.GetVault(r.Context(), reqID)
		if len(vaultMap) > 0 {
			originalLen := len(respBody)
			respBody = sanitizer.Rehydrate(respBody, vaultMap)
			if len(respBody) != originalLen {
				log.Info().Str("req_id", reqID).Msg("Vault: Rehydrated Response with Real Data")
			}
		}
	}

	// C. Watermark Injection (Invisible). Only for plain-text bodies: appending
	// zero-width characters to a JSON payload would make it invalid for the caller.
	if isWatermarkable(resp.Header.Get("Content-Type")) {
		respBody += h.watermark.Encode(userID, time.Now().Unix())
		log.Debug().Msg("Injected invisible watermark")
	}

	// Stream final response back
	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	if len(respBody) != len(respBodyBytes) {
		w.Header().Set("Content-Length", strconv.Itoa(len(respBody)))
	}

	w.WriteHeader(resp.StatusCode)
	io.WriteString(w, respBody)
}

// isWatermarkable reports whether a response body is free text we can safely
// append an invisible marker to.
func isWatermarkable(contentType string) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	switch ct {
	case "text/plain", "text/markdown", "text/x-markdown":
		return true
	default:
		return false
	}
}
