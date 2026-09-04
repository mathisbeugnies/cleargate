package api

import (
	"cleargate/pkg/crypto"
	"cleargate/pkg/policy"
	"cleargate/pkg/sanitizer"
	"cleargate/pkg/security"
	"cleargate/pkg/storage"
	"cleargate/pkg/vector"
	"encoding/json"
	"fmt"
	"net/http"
)

type SimulatorHandler struct {
	store     *storage.Store
	engine    *policy.Engine
	guard     *vector.Guard
	injector  *security.IntentClassifier
	leak      *security.LeakDetector
	sanitizer *sanitizer.Sanitizer
}

func NewSimulatorHandler(store *storage.Store, engine *policy.Engine, guard *vector.Guard, injector *security.IntentClassifier, leak *security.LeakDetector, sanitizer *sanitizer.Sanitizer) *SimulatorHandler {
	return &SimulatorHandler{
		store:     store,
		engine:    engine,
		guard:     guard,
		injector:  injector,
		leak:      leak,
		sanitizer: sanitizer,
	}
}

type SimulationRequest struct {
	Prompt string `json:"prompt"`
}

type SimulationStep struct {
	Name    string                 `json:"name"`
	Status  string                 `json:"status"` // "PASS", "BLOCK", "MODIFY"
	Details string                 `json:"details"`
	Meta    map[string]interface{} `json:"meta,omitempty"`
}

type SimulationResponse struct {
	Steps       []SimulationStep `json:"steps"`
	FinalPrompt string           `json:"final_prompt"`
	Verdict     string           `json:"verdict"` // "PASS" or "BLOCK"
}

func (h *SimulatorHandler) Simulate(w http.ResponseWriter, r *http.Request) {
	// 1. Auth & Config
	claims, ok := UserFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req SimulationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid Request")
		return
	}

	// Fetch Policy
	jsonConfig, err := h.store.GetPolicyByOrgID(claims.OrgID)
	orgConfig := policy.DefaultConfig
	if err == nil {
		orgConfig = h.engine.ParseConfig(jsonConfig)
	}

	var steps []SimulationStep
	currentPrompt := req.Prompt
	verdict := "PASS"

	// 1. Step: Normalization
	normalizedPrompt, isObfuscated := security.NormalizePrompt(currentPrompt)
	normStep := SimulationStep{Name: "Text Normalization", Status: "PASS", Details: "No obfuscation detected"}
	if isObfuscated {
		normStep.Status = "WARN" // Or INFO?
		normStep.Details = "Obfuscation Detected (Base64/URL/HTML/Hidden)"
		normStep.Meta = map[string]interface{}{"original_length": len(currentPrompt), "decoding": "applied"}
		currentPrompt = normalizedPrompt // Use normalized for next steps
	}
	steps = append(steps, normStep) // Add as first step

	// 2. Step: Anomaly Detection (Simulation)
	anomalyStep := SimulationStep{Name: "Anomaly Detection", Status: "PASS", Details: "User Baseline Clean (Simulated)"}
	if !orgConfig.AnomalyDetection {
		anomalyStep.Status = "SKIP"
		anomalyStep.Details = "Disabled in Policy"
	} else if isObfuscated {
		// If obfuscated, we simulate the risk score increase
		anomalyStep.Details = "Risk Score increased (+30%) due to Obfuscation"
	}
	steps = append(steps, anomalyStep)

	// 2. Step 0: Prompt Leak Protection
	leakStep := SimulationStep{Name: "Prompt Leak Protection", Status: "PASS", Details: "No leak attempt detected"}
	if orgConfig.PromptLeaking {
		if leaked, reason := h.leak.Detect(currentPrompt); leaked {
			leakStep.Status = "BLOCK"
			leakStep.Details = fmt.Sprintf("Blocked: %s", reason)
			verdict = "BLOCK"
		}
	} else {
		leakStep.Status = "SKIP"
		leakStep.Details = "Disabled in Policy"
	}
	steps = append(steps, leakStep)

	if verdict == "BLOCK" {
		response(w, steps, currentPrompt, verdict)
		return
	}

	// 2. Step 1: Prompt Injection
	injStep := SimulationStep{Name: "Prompt Injection Defense", Status: "PASS", Details: "No injection detected"}
	if orgConfig.PromptInjection {
		if blocked, score, reason := h.injector.Detect(currentPrompt, orgConfig.InjectionThreshold); blocked {
			injStep.Status = "BLOCK"
			injStep.Details = fmt.Sprintf("Blocked: %s", reason)
			injStep.Meta = map[string]interface{}{"score": score, "threshold": orgConfig.InjectionThreshold}
			verdict = "BLOCK"
		} else {
			injStep.Meta = map[string]interface{}{"score": score}
		}
	} else {
		injStep.Status = "SKIP"
		injStep.Details = "Disabled in Policy"
	}
	steps = append(steps, injStep)

	// If blocked, stop here or continue showing what *would* happen?
	// Real pipeline stops. Simulator stops too for accuracy.
	if verdict == "BLOCK" {
		response(w, steps, currentPrompt, verdict)
		return
	}

	// 3. Step 2: Vector Guard
	vecStep := SimulationStep{Name: "Vector Semantic Guard", Status: "PASS", Details: "No semantic violation"}
	if orgConfig.VectorGuard {
		if blocked, score, reason := h.guard.IsBlocked(currentPrompt, claims.OrgID); blocked {
			vecStep.Status = "BLOCK"
			vecStep.Details = fmt.Sprintf("Violates Forbidden Sector: %s", reason)
			vecStep.Meta = map[string]interface{}{"score": score}
			verdict = "BLOCK"
		} else {
			vecStep.Meta = map[string]interface{}{"score": score}
		}
	} else {
		vecStep.Status = "SKIP"
		vecStep.Details = "Disabled in Policy"
	}
	steps = append(steps, vecStep)

	if verdict == "BLOCK" {
		response(w, steps, currentPrompt, verdict)
		return
	}

	// 4. Step 3: PII Sanitizer
	piiStep := SimulationStep{Name: "DLP / PII Sanitizer", Status: "PASS", Details: "No sensitive data found"}
	sanResult := h.sanitizer.Sanitize(currentPrompt, &sanitizer.Config{
		RedactEmails:     orgConfig.EmailRedaction,
		RedactPhones:     orgConfig.PhoneRedaction,
		RedactAPIKeys:    orgConfig.ApiKeyProtection,
		RedactSourceCode: orgConfig.SourceCodeDLP,
		EntropyScanner:   orgConfig.EntropyScanner,
		NerEnabled:       orgConfig.NerEnabled,
		MedicalCheck:     orgConfig.MedicalCheck,
	})

	if sanResult.SanitizedBody != currentPrompt {
		piiStep.Status = "MODIFY"
		piiStep.Details = fmt.Sprintf("Redacted %d items", len(sanResult.Mapping))

		// Encrypt for Display if Key Exists
		// We'll try to fetch key first.
		pubKey, _ := h.store.GetPublicKey(claims.OrgID)

		displayMapping := make(map[string]string)
		for k, v := range sanResult.Mapping {
			if pubKey != "" {
				enc, err := crypto.EncryptRSA(v, pubKey)
				if err == nil {
					displayMapping[k] = "RSA:" + enc
				} else {
					displayMapping[k] = v + " (Encryption Failed)"
				}
			} else {
				displayMapping[k] = v + " (Unencrypted - No Key)"
			}
		}

		piiStep.Meta = map[string]interface{}{"mapping": displayMapping}
		currentPrompt = sanResult.SanitizedBody
	}
	steps = append(steps, piiStep)

	response(w, steps, currentPrompt, verdict)
}

func response(w http.ResponseWriter, steps []SimulationStep, final string, verdict string) {
	json.NewEncoder(w).Encode(SimulationResponse{
		Steps:       steps,
		FinalPrompt: final,
		Verdict:     verdict,
	})
}
