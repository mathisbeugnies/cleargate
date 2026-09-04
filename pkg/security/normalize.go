package security

import (
	"encoding/base64"
	"html"
	"net/url"
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// NormalizePrompt cleanses input text of common obfuscation techniques.
// Returns the normalized text and a boolean indicating if significant obfuscation was detected.
func NormalizePrompt(input string) (string, bool) {
	obfuscated := false
	original := input

	// 1. Unicode Normalization (NFKC - Compatibility Decomposition)
	// Handles homoglyphs and compatibility characters
	cleaned := norm.NFKC.String(input)

	// 2. Remove Invisible Characters (Zero-width spaces, etc.)
	// Range: \u200B-\u200F, \uFEFF, etc.
	invisibleRx := regexp.MustCompile(`[\x{200B}-\x{200F}\x{FEFF}]`)
	if invisibleRx.MatchString(cleaned) {
		cleaned = invisibleRx.ReplaceAllString(cleaned, "")
		obfuscated = true // Hidden characters are suspicious
	}

	// 3. HTML Entity Decoding
	decodedHTML := html.UnescapeString(cleaned)
	if decodedHTML != cleaned {
		cleaned = decodedHTML
		// excessive HTML usage might be suspicious, but common in some inputs.
		// flagging as obfuscated only if it changed significantly? keeping simple for now.
	}

	// 4. URL Decoding
	if strings.Contains(cleaned, "%") {
		decodedURL, err := url.QueryUnescape(cleaned)
		if err == nil && decodedURL != cleaned {
			cleaned = decodedURL
			// URL encoding used inside a prompt is often for evasion
			obfuscated = true
		}
	}

	// 5. Base64 Detection & Decoding
	// Heuristic: Check if string looks like Base64 (length > 20, no spaces, padding)
	// Note: Aggressive Base64 decoding can produce garbage on normal text.
	// We only decode if the entire string or large chunks look like Base64.
	// For this MVP, we try to decode the WHOLE string if it matches typical Base64 pattern.
	base64Pattern := regexp.MustCompile(`^[A-Za-z0-9+/=]{20,}$`)
	if base64Pattern.MatchString(strings.TrimSpace(cleaned)) {
		decodedBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cleaned))
		if err == nil {
			// Check if result is readable text (mostly printable)
			if isReadable(decodedBytes) {
				cleaned = string(decodedBytes)
				obfuscated = true
			}
		}
	}

	// Double check Unicode after decoding
	cleaned = norm.NFKC.String(cleaned)

	// If the text changed significantly and wasn't just simple whitespace normalization
	if cleaned != original && !obfuscated {
		// e.g. HTML entities were decoded
		// We flag strictly if we found invisible chars or Base64/URL encoding.
	}

	return cleaned, obfuscated
}

// isReadable checks if a byte slice consists mainly of printable characters
func isReadable(data []byte) bool {
	printable := 0
	for _, b := range data {
		r := rune(b)
		if unicode.IsPrint(r) || unicode.IsSpace(r) {
			printable++
		}
	}
	return float64(printable)/float64(len(data)) > 0.9
}
