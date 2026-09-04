package provider

func NewAnthropicProvider() Provider {
	p := newHTTPProvider("Anthropic", "ANTHROPIC_BASE_URL", "https://api.anthropic.com", "/v1/messages")
	// Anthropic requires this header; supply a default if the caller omitted it.
	p.defaultHeaders = map[string]string{"anthropic-version": "2023-06-01"}
	return p
}
