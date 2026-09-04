package provider

func NewOpenAIProvider() Provider {
	return newHTTPProvider("OpenAI", "OPENAI_BASE_URL", "https://api.openai.com", "/v1/chat/completions")
}
