package security

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// LlamaGuardClient implements PromptGuardClient using a local Ollama instance.
type LlamaGuardClient struct {
	BaseURL    string
	ModelName  string
	HTTPClient *http.Client
}

// NewLlamaGuardClient creates a new client.
// baseURL: usually "http://localhost:11434"
// model: usually "llama-guard:latest"
func NewLlamaGuardClient(baseURL, model string) *LlamaGuardClient {
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}
	if model == "" {
		model = "llama-guard:latest"
	}

	return &LlamaGuardClient{
		BaseURL:   baseURL,
		ModelName: model,
		HTTPClient: &http.Client{
			// LlamaGuard can be slow depending on hardware, but we don't want to block forever.
			Timeout: 10 * time.Second,
		},
	}
}

// OllamaRequest structure
type OllamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

// OllamaResponse structure
type OllamaResponse struct {
	Response string `json:"response"`
	Done     bool   `json:"done"`
}

// Classify sends the prompt to LlamaGuard via Ollama.
// Returns true if blocked (unsafe), the risk score (0.0 or 1.0), and error.
// LlamaGuard outputs "safe" or "unsafe\n[category]".
func (c *LlamaGuardClient) Classify(text string) (bool, float64, error) {
	// LlamaGuard Template required for correct processing
	// We wrap the user prompt in the standard conversation template.
	// Simplified wrapper:
	fullPrompt := fmt.Sprintf("[INST] Task: Check if there is unsafe content in 'User' messages in output 'Agent' messages according to our safety policy with the below categories.\n\n<BEGIN UNSAFE CONTENT CATEGORIES>\nO1: Violence and Hate.\nO2: Sexual Content.\nO3: Criminal Planning.\nO4: Guns and Illegal Weapons.\nO5: Regulated or Controlled Substances.\nO6: Self-Harm.\n<END UNSAFE CONTENT CATEGORIES>\n\n<BEGIN CONVERSATION>\nUser: %s\n\nAgent: [/INST]", text)

	reqBody := OllamaRequest{
		Model:  c.ModelName,
		Prompt: fullPrompt,
		Stream: false,
	}

	jsonBytes, err := json.Marshal(reqBody)
	if err != nil {
		return false, 0, err
	}

	resp, err := c.HTTPClient.Post(c.BaseURL+"/api/generate", "application/json", bytes.NewBuffer(jsonBytes))
	if err != nil {
		// Log connection error but don't crash. Return error so caller knows check failed.
		log.Error().Err(err).Msg("Failed to connect to Ollama (LlamaGuard)")
		return false, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return false, 0, fmt.Errorf("ollama returned status: %d", resp.StatusCode)
	}

	var ollamaResp OllamaResponse
	if err := json.NewDecoder(resp.Body).Decode(&ollamaResp); err != nil {
		return false, 0, err
	}

	output := strings.TrimSpace(ollamaResp.Response)
	log.Debug().Str("output", output).Msg("LlamaGuard raw output")

	if strings.HasPrefix(output, "unsafe") {
		// Parse category if needed, for now just block.
		return true, 1.0, nil
	}

	return false, 0.0, nil
}
