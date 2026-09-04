package sanitizer

import (
	"math"
	"strings"
)

// CalculateShannonEntropy returns the Shannon entropy of a string (bits per symbol).
func CalculateShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]float64)
	for _, char := range s {
		freq[char]++
	}

	entropy := 0.0
	length := float64(len(s))

	for _, count := range freq {
		p := count / length
		entropy -= p * math.Log2(p)
	}

	return entropy
}

// IsHighEntropy checks if a token is likely a machine-generated secret or password.
// Criteria:
// 1. Length >= 8
// 2. Entropy > 3.0 OR (HasDigit + HasSpecial + HasUpper + HasLower)
// 3. Not a Placeholder
func IsHighEntropy(token string) bool {
	if len(token) < 8 {
		return false
	}

	// Avoid re-redacting placeholders
	if strings.HasPrefix(token, "[") && strings.HasSuffix(token, "]") {
		return false
	}

	// Avoid common URLs (heuristic)
	if strings.HasPrefix(token, "http") || strings.Contains(token, "://") {
		return false
	}

	entropy := CalculateShannonEntropy(token)

	// Character class analysis
	hasUpper := strings.ContainsAny(token, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	hasLower := strings.ContainsAny(token, "abcdefghijklmnopqrstuvwxyz")
	hasDigit := strings.ContainsAny(token, "0123456789")
	hasSpecial := strings.ContainsAny(token, "!@#$%^&*()-_=+,.?/:;{}[]|")

	complexity := 0
	if hasUpper {
		complexity++
	}
	if hasLower {
		complexity++
	}
	if hasDigit {
		complexity++
	}
	if hasSpecial {
		complexity++
	}

	// If it looks like a complex password (3+ classes)
	// Must contain at least one digit to avoid false positives on hyphenated words (e.g. "Explique-moi")
	if complexity >= 3 && len(token) >= 10 && hasDigit {
		return true
	}

	// 'Azerty123!' -> 10 chars. Upper, Lower, Digit, Special. Complexity 4. Caught.
	// 'Explique-moi' -> 12 chars. Upper, Lower, Special. No Digit. Complexity 3. SKIPPED.

	// Original Entropy check
	return entropy > 3.8
}
