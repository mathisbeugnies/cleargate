package security

import (
	"fmt"
	"strings"
)

// PromptGuardClient defines the interface for external classification (e.g., Llama-Guard).
// It returns blocked status, a risk score, and an potential error.
type PromptGuardClient interface {
	Classify(text string) (bool, float64, error)
}

// IntentClassifier analyzes prompts to detect malicious intent structures,
// including jailbreaks, role manipulation, and harmful instructions.
type IntentClassifier struct {
	GuardClient PromptGuardClient // Optional external model client
}

// NewIntentClassifier creates a new instance of IntentClassifier with an optional external guard client.
func NewIntentClassifier(client PromptGuardClient) *IntentClassifier {
	return &IntentClassifier{
		GuardClient: client,
	}
}

// Detect is the main entry point for intent analysis.
// It combines external model checks (if available) with local heuristic analysis.
func (c *IntentClassifier) Detect(text string, threshold float64) (bool, float64, string) {
	// 1. External Model Check (if configured)
	if c.GuardClient != nil {
		blocked, score, err := c.GuardClient.Classify(text)
		if err == nil && blocked {
			return true, score, "PromptGuard: Malicious Content Detected"
		}
	}

	// 2. Smart Fallback: Local Heuristic Analysis
	// Check for Long Prompt (Sliding Window Scan)
	words := strings.Fields(text)
	var riskScore float64

	if len(words) > 1000 {
		riskScore = c.scanWindowed(words)
	} else {
		riskScore = c.PredictRisk(text)
	}

	if riskScore >= threshold {
		// For long prompts, we might want to know WHICH window triggered it, but simplified for now.
		return true, riskScore, fmt.Sprintf("Intent Analysis Block: Risk Score %.2f", riskScore)
	}

	return false, riskScore, ""
}

// scanWindowed performs sliding window analysis
func (c *IntentClassifier) scanWindowed(words []string) float64 {
	windowSize := 500
	overlap := 100
	step := windowSize - overlap // 400
	maxRisk := 0.0

	for i := 0; i < len(words); i += step {
		end := i + windowSize
		if end > len(words) {
			end = len(words)
		}

		windowText := strings.Join(words[i:end], " ")
		risk := c.PredictRisk(windowText)

		if risk > maxRisk {
			maxRisk = risk
		}

		// Optimization: Fail fast if we hit a critical score that guarantees a block
		if maxRisk >= 1.0 {
			return 1.0
		}
	}
	return maxRisk
}

// PredictRisk calculates the "Attack Weight" of a text based on heuristic patterns.
// It analyzes structure, conflicts, and attack vectors (persuasion, urgency, secrecy).
func (c *IntentClassifier) PredictRisk(text string) float64 {
	score := 0.0
	lower := strings.ToLower(text)

	// A. Structure Analysis: Role Manipulation (0.4)
	if c.HasRoleManipulation(lower) {
		score += 0.4
	}

	// B. Conflict Detection: Ignore Rules (0.5)
	if c.HasConflict(lower) {
		score += 0.5
	}

	// C. Attack Weighting (Persuasion, Urgency, Secrecy)
	score += c.CalculateAttackWeight(lower)

	// Max Score 1.0 (or higher to be sure)
	if score > 1.0 {
		return 1.0
	}
	return score
}

func (c *IntentClassifier) HasRoleManipulation(text string) bool {
	patterns := []string{
		"tu es maintenant", "you are now",
		"agis en tant que", "act as",
		"mode dan", "dan mode",
		"simulation", "roleplay",
		"adopt the persona",
		"ignore all previous", // Often starts a role definition
	}
	for _, p := range patterns {
		if strings.Contains(text, p) {
			return true
		}
	}
	return false
}

func (c *IntentClassifier) HasConflict(text string) bool {
	// Explicit contradictions to safety rules
	if (strings.Contains(text, "ignore") || strings.Contains(text, "oublie") || strings.Contains(text, "bypass")) &&
		(strings.Contains(text, "rule") || strings.Contains(text, "règle") || strings.Contains(text, "instruction") || strings.Contains(text, "safety")) {
		return true
	}
	return false
}

func (c *IntentClassifier) CalculateAttackWeight(text string) float64 {
	weight := 0.0

	// 1. Urgency / Pressure
	urgencyWords := []string{"maintenant", "now", "urgent", "immediately", "vite", "fast", "asap"}
	for _, w := range urgencyWords {
		if strings.Contains(text, w) {
			weight += 0.1
			break // Max 0.1 for urgency category
		}
	}

	// 2. Secrecy / Hide Information
	secrecyWords := []string{"secret", "hidden", "caché", "confidentiel", "just between us", "entre nous", "ne dis pas"}
	for _, w := range secrecyWords {
		if strings.Contains(text, w) {
			weight += 0.15
			break
		}
	}

	// 3. Persuasion / Authority
	persuasionWords := []string{"please", "s'il te plait", "i need", "j'ai besoin", "important", "authorized", "admin"}
	for _, w := range persuasionWords {
		if strings.Contains(text, w) {
			weight += 0.05
			break
		}
	}

	return weight
}

// MockLlamaGuard implements PromptGuardClient for testing
type MockLlamaGuard struct{}

func (m *MockLlamaGuard) Classify(text string) (bool, float64, error) {
	// Mock: Always clean unless specific trigger
	if strings.Contains(text, "LLAMA_GUARD_TRIGGER") {
		return true, 0.99, nil
	}
	return false, 0.0, nil
}
