package sanitizer

import (
	"strings"
	"testing"
)

func TestSanitizeRedactsEmail(t *testing.T) {
	s := NewSanitizer()
	res := s.Sanitize("contact me at john.doe@example.com please", &Config{RedactEmails: true})

	if strings.Contains(res.SanitizedBody, "john.doe@example.com") {
		t.Fatalf("email not redacted: %q", res.SanitizedBody)
	}
	if len(res.Mapping) == 0 {
		t.Fatal("expected at least one mapping entry")
	}
}

func TestSanitizeLeavesCleanTextUntouched(t *testing.T) {
	s := NewSanitizer()
	in := "summarize the quarterly sales report for the northeast region"
	res := s.Sanitize(in, &Config{RedactEmails: true, RedactPhones: true, RedactAPIKeys: true})

	if res.SanitizedBody != in {
		t.Fatalf("clean text was modified: %q -> %q", in, res.SanitizedBody)
	}
}

func TestSanitizeRedactsPhoneFormats(t *testing.T) {
	s := NewSanitizer()
	cases := []string{
		"call me at (555) 123-4567 today",
		"my number is 06 12 34 56 78",
		"reach me on +33 6 12 34 56 78 anytime",
		"UK office +44 20 7946 0958",
	}
	for _, in := range cases {
		res := s.Sanitize(in, &Config{RedactPhones: true})
		if res.SanitizedBody == in {
			t.Errorf("phone not redacted in %q -> %q", in, res.SanitizedBody)
		}
	}

	// Should not eat ordinary numbers in prose.
	clean := "we shipped 3 releases in 2024 and 2025"
	if got := s.Sanitize(clean, &Config{RedactPhones: true}).SanitizedBody; got != clean {
		t.Errorf("false positive on %q -> %q", clean, got)
	}
}

func TestSanitizeRespectsDisabledChecks(t *testing.T) {
	s := NewSanitizer()
	res := s.Sanitize("my email is john@example.com", &Config{RedactEmails: false})

	if !strings.Contains(res.SanitizedBody, "john@example.com") {
		t.Fatalf("email redacted even though RedactEmails was false: %q", res.SanitizedBody)
	}
}
