package sanitizer

import (
	"fmt"
	"regexp"
)

var (
	// Example patterns - in production use a robust library or extensive list
	awsKeyRegex    = regexp.MustCompile(`(AKIA|ASIA)[0-9A-Z]{16}`)
	githubKeyRegex = regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`)
	stripeKeyRegex = regexp.MustCompile(`sk_live_[a-zA-Z0-9]{24}`)
	openaiKeyRegex = regexp.MustCompile(`sk-[a-zA-Z0-9]{10,}`) // Generic sk- prefix
)

type SecretMatch struct {
	Type  string
	Value string
}

func ScanSecrets(input string) []SecretMatch {
	var matches []SecretMatch

	for _, m := range awsKeyRegex.FindAllString(input, -1) {
		matches = append(matches, SecretMatch{Type: "AWS", Value: m})
	}
	for _, m := range githubKeyRegex.FindAllString(input, -1) {
		matches = append(matches, SecretMatch{Type: "GitHub", Value: m})
	}
	for _, m := range stripeKeyRegex.FindAllString(input, -1) {
		matches = append(matches, SecretMatch{Type: "Stripe", Value: m})
	}
	for _, m := range openaiKeyRegex.FindAllString(input, -1) {
		matches = append(matches, SecretMatch{Type: "OpenAI", Value: m})
	}

	return matches
}

func MaskSecret(secretType string, index int) string {
	return fmt.Sprintf("[%s_KEY_%d]", secretType, index+1)
}
