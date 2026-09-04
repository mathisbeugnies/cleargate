package policy

import (
	"encoding/json"
)

const (
	SensitivityLow    = "LOW"
	SensitivityMedium = "MEDIUM"
	SensitivityHigh   = "HIGH"
)

// GlobalConfig defines the security configuration for an organization.
type GlobalConfig struct {
	Sensitivity        string  `json:"sensitivity"` // LOW, MEDIUM, HIGH
	EmailRedaction     bool    `json:"email_redaction"`
	PhoneRedaction     bool    `json:"phone_redaction"`
	ApiKeyProtection   bool    `json:"api_key_detection"`
	SourceCodeDLP      bool    `json:"source_code_dlp"`
	PromptInjection    bool    `json:"prompt_injection"`
	InjectionThreshold float64 `json:"injection_threshold"`
	VectorGuard        bool    `json:"vector_guard"`
	EntropyScanner     bool    `json:"entropy_scanner"`
	NerEnabled         bool    `json:"ner_enabled"`
	MedicalCheck       bool    `json:"medical_check"`
	PromptLeaking      bool    `json:"prompt_leaking"`
	TokenVault         bool    `json:"token_vault"` // [NEW] Vault Feature
	OutputControl      bool    `json:"output_control"`
	AnomalyDetection   bool    `json:"anomaly_detection"`
}

// DefaultConfig provides a standard safe configuration.
var DefaultConfig = GlobalConfig{
	Sensitivity:        SensitivityMedium,
	EmailRedaction:     true,
	PhoneRedaction:     true,
	ApiKeyProtection:   true,
	SourceCodeDLP:      true,
	PromptInjection:    true,
	InjectionThreshold: 0.8,
	VectorGuard:        true,
	EntropyScanner:     false,
	NerEnabled:         false,
	MedicalCheck:       false,
	PromptLeaking:      true,
	OutputControl:      true,
	AnomalyDetection:   true,
}

// Engine ensures policies are applied correctly based on the context.
type Engine struct{}

// NewEngine creates a new instance of the Policy Engine.
func NewEngine() *Engine {
	return &Engine{}
}

// ParseConfig converts a JSON string into a GlobalConfig object, applying defaults if needed.
func (e *Engine) ParseConfig(jsonConfig string) GlobalConfig {
	if jsonConfig == "" || jsonConfig == "{}" {
		return DefaultConfig
	}
	cfg := DefaultConfig
	if err := json.Unmarshal([]byte(jsonConfig), &cfg); err != nil {
		return DefaultConfig
	}
	// Ensure Sensitivity is set
	if cfg.Sensitivity == "" {
		cfg.Sensitivity = SensitivityMedium
	}
	return cfg
}

// RiskContext aggregates all security signals collected during the request analysis phase.
type RiskContext struct {
	InjectionScore  float64
	InjectionReason string

	VectorScore  float32
	VectorReason string

	LeakDetected bool
	LeakReason   string

	Obfuscated bool

	PIICount   int
	HasPerson  bool
	HasMedical bool

	OutOfDomain bool // [NEW] Domain Check

	AnomalyScore int // From cache/anomaly detector
}

// Verdict represents the final decision of the Policy Engine.
type Verdict struct {
	Action string // PASS, BLOCK, MODIFY (MASK)
	Reason string
	Score  int
}

// AnalyzeRisk evaluates the RiskContext against the GlobalConfig to produce a Verdict.
// It implements the Contextual Risk Matrix logic.
func (e *Engine) AnalyzeRisk(ctx RiskContext, cfg GlobalConfig) Verdict {
	score := 0
	action := "PASS"
	reason := ""

	// 1. Base Scores
	if ctx.Obfuscated {
		score += 30
	}
	if ctx.OutOfDomain {
		score += 30
		if reason == "" {
			reason = "Out-of-Domain Anomaly"
		}
	}
	if ctx.LeakDetected {
		score += 100
		reason = "Prompt Leak: " + ctx.LeakReason
	}
	if ctx.InjectionScore > 0 {
		score += int(ctx.InjectionScore * 100)
	}
	if ctx.VectorScore > 0 {
		score += int(ctx.VectorScore * 100)
	}

	// 2. Matrix Logic (Combinations)

	// A. Injection + Obfuscation = Critical
	if ctx.InjectionScore > 0.6 && ctx.Obfuscated {
		score = 100 // Force Critical
		reason = "CRITICAL: Obfuscated Injection Attempt"
	}

	// B. Person + Medical = Health Data Risk
	if ctx.HasPerson && ctx.HasMedical {
		score = 100
		reason = "CRITICAL: Health Data Correlation (Person + Medical)"
	} else if ctx.HasPerson {
		// Just Person -> Sensitive, but not Block (unless High Sensitivity)
		score += 20 // Warning level
		if reason == "" {
			reason = "PII Detected (Person Name)"
		}
	}

	// 3. Sensitivity Adjustment
	threshold := 80 // Default High Threshold
	switch cfg.Sensitivity {
	case SensitivityLow:
		threshold = 90
		if score < 50 {
			score = 0
		} // Ignore low noise
	case SensitivityHigh:
		threshold = 60
		score += 10 // bias upwards
	}

	// 4. Final Decision
	if score >= threshold {
		action = "BLOCK"
		if reason == "" {
			reason = "High Risk Score Exceeded"
		}
	} else if ctx.PIICount > 0 || ctx.HasPerson {
		action = "MODIFY" // Sanitize/Redact
		if reason == "" {
			reason = "Sensitive Data Redacted"
		}
	}

	// Override for specific hard blocks (Leak, Vector) if config enabled,
	// but usually score handles it.
	// Let's rely on score unless explicit module disable needed,
	// but context assumes modules ran only if enabled.

	// Vector Guard Hard Block (if extremely high match)
	if ctx.VectorScore > 0.82 { // Original threshold
		action = "BLOCK"
		reason = "Vector Guard Violation: " + ctx.VectorReason
	}

	return Verdict{Action: action, Reason: reason, Score: score}
}
