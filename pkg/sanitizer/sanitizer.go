package sanitizer

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

var (
	emailRegex = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	// Covers North American 3-3-4, E.164 international (+CC ...), and national
	// numbers written with a leading trunk zero (FR/UK/DE style).
	phoneRegex = regexp.MustCompile(`(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]?\d{3}[-. ]?\d{4}|\+\d{1,3}(?:[ .\-]?\d{1,4}){3,8}|\b0\d(?:[ .\-]?\d){7,9}\b`)
	ibanRegex  = regexp.MustCompile(`[A-Z]{2}\d{2}\s*([0-9A-Z]{4}\s*){4,8}`) // Basic IBAN with optional spaces
	// Credit Card: Visa (4xxx), Mastercard (5[1-5]xx), Amex (3[47]x), Discover (6011/65).
	// Simplified to 13-19 digits with optional separators.
	creditCardRegex      = regexp.MustCompile(`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b`)
	passwordContextRegex = regexp.MustCompile(`(?i)\b(password|passwd|pwd|mdp|mot de passe|secret)\s*[:=]\s*["']?([^\s"']+)["']?`)
)

// Config defines the sanitization rules for a request.
type Config struct {
	RedactEmails     bool
	RedactPhones     bool
	RedactIBANs      bool
	RedactAPIKeys    bool
	RedactSourceCode bool
	EntropyScanner   bool
	NerEnabled       bool
	MedicalCheck     bool
	UseVault         bool // [NEW] Token Vault Mode
}

// ScanResult contains the sanitized text, the mapping of redacted items, and risk metadata.
type ScanResult struct {
	SanitizedBody string
	Mapping       map[string]string
	RiskScore     int
	Alerts        []string
}

// Sanitizer provides methods to detect and redact sensitive PII and secrets from text.
type Sanitizer struct{}

// NewSanitizer creates a new instance of Sanitizer.
func NewSanitizer() *Sanitizer {
	return &Sanitizer{}
}

// Sanitize processes the input text according to the provided configuration.
// It returns a ScanResult containing the sanitized text and detailed findings.
func (s *Sanitizer) Sanitize(input string, config *Config) ScanResult {
	mapping := make(map[string]string)
	sanitized := input
	var alerts []string
	piiCount := 0

	// 1. PII Scan (Email/Phone/IBAN)
	if config.RedactEmails {
		emailMatches := emailRegex.FindAllString(sanitized, -1)
		for i, match := range emailMatches {
			placeholder := fmt.Sprintf("[EMAIL_%d]", i+1)
			if config.UseVault {
				placeholder = fmt.Sprintf("[EMAIL_%s]", uuid.New().String())
			}
			mapping[placeholder] = match
			sanitized = strings.Replace(sanitized, match, placeholder, 1)
		}
		piiCount += len(emailMatches)
	}

	if config.RedactPhones {
		phoneMatches := phoneRegex.FindAllString(sanitized, -1)
		for i, match := range phoneMatches {
			placeholder := fmt.Sprintf("[PHONE_%d]", i+1)
			if config.UseVault {
				placeholder = fmt.Sprintf("[PHONE_%s]", uuid.New().String())
			}
			mapping[placeholder] = match
			sanitized = strings.Replace(sanitized, match, placeholder, 1)
		}
		piiCount += len(phoneMatches)
	}

	if config.RedactIBANs || config.RedactEmails { // Fallback to Email flag for PII bundle
		ibanMatches := ibanRegex.FindAllString(sanitized, -1)
		for _, match := range ibanMatches {
			placeholder := "[IBAN_MASKED]"
			mapping[placeholder] = match
			sanitized = strings.Replace(sanitized, match, placeholder, 1)
			alerts = append(alerts, "IBAN Detected")
			piiCount++
		}

		// Credit Cards
		ccMatches := creditCardRegex.FindAllString(sanitized, -1)
		for i, match := range ccMatches {
			if !strings.Contains(match, "[") {
				placeholder := fmt.Sprintf("[CREDIT_CARD_%d]", i+1)
				mapping[placeholder] = match
				sanitized = strings.Replace(sanitized, match, placeholder, 1)
				alerts = append(alerts, "Financial Data (Credit Card) Detected")
				piiCount++
			}
		}
	}

	// Always checking for Password Context assignments if any PII/Secret check is on?
	// Or maybe entropy? Let's check if EntropyScanner or RedactAPIKeys is on.
	if config.EntropyScanner || config.RedactAPIKeys {
		passMatches := passwordContextRegex.FindAllStringSubmatch(sanitized, -1)
		for i, match := range passMatches {
			if len(match) > 2 {
				secretVal := match[2]
				if strings.HasPrefix(secretVal, "[") && strings.HasSuffix(secretVal, "]") {
					continue
				}
				placeholder := fmt.Sprintf("[PASSWORD_CONTEXT_%d]", i+1)
				mapping[placeholder] = secretVal
				sanitized = strings.Replace(sanitized, secretVal, placeholder, 1) // careful with substring replacement
				alerts = append(alerts, "Password Assignment Detected")
			}
		}
	}

	// 2. NER Scan (Person, Location, Org) - Enhanced with Presidio
	if config.NerEnabled {
		var entities []Entity

		// Try Presidio if enabled (or default for NER?)
		// Integration point:
		// We use the internal presidio client.
		pClient := NewPresidioClient("") // Default URL
		presidioEntities, _ := pClient.Analyze(sanitized)
		entities = append(entities, presidioEntities...)

		// Fallback/Complement with basic Regex NER
		regexEntities := ScanNER(sanitized)
		entities = append(entities, regexEntities...)

		for i, ent := range entities {
			placeholder := ""
			switch ent.Type {
			case EntityPerson:
				if config.UseVault {
					placeholder = fmt.Sprintf("[PERSON_%s]", uuid.New().String())
				} else {
					placeholder = fmt.Sprintf("[PERSON_NAME_%d]", i+1)
				}
			case EntityLocation:
				if config.UseVault {
					placeholder = fmt.Sprintf("[LOCATION_%s]", uuid.New().String())
				} else {
					placeholder = fmt.Sprintf("[LOCATION_%d]", i+1)
				}
			case EntityOrg:
				if config.UseVault {
					placeholder = fmt.Sprintf("[ORG_%s]", uuid.New().String())
				} else {
					placeholder = fmt.Sprintf("[ORG_%d]", i+1)
				}
			default:
				if config.UseVault {
					placeholder = fmt.Sprintf("[ENTITY_%s]", uuid.New().String())
				} else {
					placeholder = fmt.Sprintf("[SENSITIVE_ENTITY_%d]", i+1)
				}
			}

			if placeholder != "" {
				// Only replace if we haven't already (simple dedup)
				if _, exists := mapping[placeholder]; !exists {
					if strings.Contains(sanitized, ent.Value) {
						mapping[placeholder] = ent.Value
						sanitized = strings.Replace(sanitized, ent.Value, placeholder, 1)
						piiCount++
						alerts = append(alerts, fmt.Sprintf("NER Detected: %s", ent.Type))
					}
				}
			}
		}

		// Medical Correlation (Check Original input or Sanitized? Check input implies we detected PERSON before redaction.
		// ScanNER returned entities from 'sanitized' (which might have EMAILs redacted, but Names are visible if logic is here).
		// Wait, we just redacted Names above. So we know if we found Persons.
		if config.MedicalCheck {
			medTerms := ScanMedical(input) // Scan original for medical terms
			if len(medTerms) > 0 {
				if CorrelationCheck(entities, medTerms) { // entities contains PERSONs found
					alerts = append(alerts, fmt.Sprintf("Health Data Risk: %d medical terms associated with Person", len(medTerms)))
				}
				// Also alert on med terms alone? Maybe just Info
				// alerts = append(alerts, "Medical Terms found")
			}
		}
	}

	// 3. Secret Scan
	if config.RedactAPIKeys {
		secrets := ScanSecrets(sanitized)
		for i, sec := range secrets {
			placeholder := MaskSecret(sec.Type, i)
			mapping[placeholder] = sec.Value
			sanitized = strings.Replace(sanitized, sec.Value, placeholder, 1)
			alerts = append(alerts, fmt.Sprintf("Secret Detected: %s", sec.Type))
		}
	}

	// 3. Entropy Scan (New)
	if config.EntropyScanner {
		// Split by whitespace to find tokens
		// Note: This is a simplistic tokenizer. Punctuation might stick to tokens.
		// A better approach splits by non-alphanumeric, but let's stick to Fields for MVP.
		tokens := strings.Fields(sanitized)
		entropyCount := 0
		for _, token := range tokens {
			// Strip common punctuation for entropy check? no, punctuation adds to entropy, which is good for secrets.
			// But "word." should probably not check "word." but "word".
			// Let's check raw token first.
			if IsHighEntropy(token) {
				placeholder := fmt.Sprintf("[HIGH_ENTROPY_SECRET_%d]", entropyCount+1)
				// Only replace if not already mapped?
				if _, exists := mapping[token]; !exists {
					mapping[placeholder] = token
					sanitized = strings.Replace(sanitized, token, placeholder, 1)
					alerts = append(alerts, "High Entropy Token Detected")
					entropyCount++
				}
			}
		}
	}

	// 4. DLP / Code Scan
	isCode := false
	if config.RedactSourceCode {
		isCode, _ = DetectCode(input)
		if isCode {
			alerts = append(alerts, "Source Code Detected")
			// We don't necessarily REDACT code unless logic exists, but we alert.
		}
	}

	// 5. Calculate Risk
	risk := CalculateRisk(piiCount, len(alerts), isCode) // secrets count from alerts?

	return ScanResult{
		SanitizedBody: sanitized,
		Mapping:       mapping,
		RiskScore:     risk,
		Alerts:        alerts,
	}
}

// SanitizeOutput performs a secondary safety scan on AI-generated content.
// It looks for any leaked PII or secrets that might have been generated.
func SanitizeOutput(input string) (string, bool) {
	sanitized := input
	leaked := false

	// Config for output? Assuming defaults for now or logic from before.
	// 1. Secret Scan
	// secrets := ScanSecrets(sanitized) ... need to import/use internal helper if possible.
	// Note: ScanSecrets is internal to package, so OK.

	// Implementation from before:
	secrets := ScanSecrets(sanitized)
	for _, sec := range secrets {
		sanitized = strings.ReplaceAll(sanitized, sec.Value, "[DATA_LEAK_PREVENTED]")
		leaked = true
	}

	// 2. Email Scan
	emailMatches := emailRegex.FindAllString(sanitized, -1)
	for _, m := range emailMatches {
		if !strings.HasPrefix(m, "[EMAIL_") {
			sanitized = strings.ReplaceAll(sanitized, m, "[EMAIL_DETECTED]")
			leaked = true
		}
	}

	// 3. Phone Scan
	phoneMatches := phoneRegex.FindAllString(sanitized, -1)
	for _, m := range phoneMatches {
		if !strings.HasPrefix(m, "[PHONE_") {
			sanitized = strings.ReplaceAll(sanitized, m, "[PHONE_DETECTED]")
			leaked = true
		}
	}

	// 4. IBAN Scan
	ibanMatches := ibanRegex.FindAllString(sanitized, -1)
	for _, m := range ibanMatches {
		if !strings.Contains(m, "[") { // crude check to avoid replacing existing placeholders
			sanitized = strings.ReplaceAll(sanitized, m, "[IBAN_DETECTED]")
			leaked = true
		}
	}

	// 5. Credit Card Scan
	ccMatches := creditCardRegex.FindAllString(sanitized, -1)
	for _, m := range ccMatches {
		if !strings.Contains(m, "[") {
			sanitized = strings.ReplaceAll(sanitized, m, "[CREDIT_CARD_DETECTED]")
			leaked = true
		}
	}

	// 6. Contextual Password Scan
	passMatches := passwordContextRegex.FindAllStringSubmatch(sanitized, -1)
	for _, match := range passMatches {
		if len(match) > 2 {
			secretVal := match[2]
			if strings.HasPrefix(secretVal, "[") && strings.HasSuffix(secretVal, "]") {
				continue
			}
			sanitized = strings.Replace(sanitized, secretVal, "[PASSWORD_DETECTED]", 1)
			leaked = true
		}
	}

	return sanitized, leaked
}

// Rehydrate restores the original sensitive data into the text using the provided mapping.
// This is typically used to reveal PII to authorized users after LLM processing.
func Rehydrate(input string, mapping map[string]string) string {
	rehydrated := input
	for placeholder, original := range mapping {
		rehydrated = strings.ReplaceAll(rehydrated, placeholder, original)
	}
	return rehydrated
}
