package provider

func NewMistralProvider() Provider {
	return newHTTPProvider("Mistral", "MISTRAL_BASE_URL", "https://api.mistral.ai", "/v1/chat/completions")
}
