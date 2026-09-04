package sanitizer

import (
	"io"
)

// StreamScanner wraps an io.Writer to perform on-the-fly sanitization
type StreamScanner struct {
	w       io.Writer
	buffer  []byte
	overlap int
}

func NewStreamScanner(w io.Writer) *StreamScanner {
	return &StreamScanner{
		w:       w,
		buffer:  make([]byte, 0, 4096),
		overlap: 100, // Sufficient for emails/keys
	}
}

// Write appends data to buffer, sanitizes it, and flushes safe parts
func (s *StreamScanner) Write(p []byte) (n int, err error) {
	s.buffer = append(s.buffer, p...)

	// Scan the entire buffer for PII/Secrets
	// Note: In a real efficient implementation, we would only scan the new part + overlap
	// For now, we reuse the existing SanitizeOutput logic which expects string

	// Convert buffer to string (copy)
	dirty := string(s.buffer)

	// We use the same regexes from secrets.go
	clean, _ := SanitizeOutput(dirty)

	// If the buffer grew large enough, we can flush the "safe" part
	// The "safe" part is everything except the last 'overlap' bytes
	// which might be part of an incomplete sensitive token.

	if len(clean) > s.overlap {
		toFlush := clean[:len(clean)-s.overlap]
		if _, err := s.w.Write([]byte(toFlush)); err != nil {
			return 0, err
		}

		// Reset buffer to just the remaining part (sanitized)
		// We keep the sanitized overlap in the buffer
		remaining := clean[len(clean)-s.overlap:]
		s.buffer = []byte(remaining)
	} else {
		// Keep everything in buffer if it's small
		s.buffer = []byte(clean)
	}

	return len(p), nil
}

// Close flushes the remaining buffer
func (s *StreamScanner) Close() error {
	if len(s.buffer) > 0 {
		// Sanitize one last time (already done in Write but to be sure)
		clean, _ := SanitizeOutput(string(s.buffer))
		if _, err := s.w.Write([]byte(clean)); err != nil {
			return err
		}
		s.buffer = nil
	}
	return nil
}
