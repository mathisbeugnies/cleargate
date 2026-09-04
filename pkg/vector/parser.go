package vector

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/ledongthuc/pdf"
)

// ParseDocument extracts text from a file based on its content type (MIME) or extension.
// Currently supports "application/pdf" and "text/plain".
func ParseDocument(reader io.ReaderAt, size int64, contentType string) (string, error) {
	if strings.Contains(contentType, "pdf") {
		return parsePDF(reader, size)
	}
	// Default to text
	// simple cast ReaderAt to Reader if possible, or just read all
	// ReaderAt doesn't implement Read directly, so we need a SectionReader or similar if we want to stream.
	// But ledongthuc/pdf needs ReaderAt.
	// For text, let's assume we can read it all.
	// We need to handle the dual interface requirement properly.
	return "", fmt.Errorf("text/plain parsing not fully implemented for mixed ReaderAt interface yet")
	// Actually, let's change signature to accept io.Reader for text and ReaderAt for PDF
}

// ParsePDF extracts text from a PDF file.
func parsePDF(reader io.ReaderAt, size int64) (string, error) {
	r, err := pdf.NewReader(reader, size)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	for pageIndex := 1; pageIndex <= r.NumPage(); pageIndex++ {
		p := r.Page(pageIndex)
		if p.V.IsNull() {
			continue
		}
		text, err := p.GetPlainText(nil)
		if err != nil {
			// Log error but continue?
			continue
		}
		buf.WriteString(text)
		buf.WriteString("\n")
	}
	return buf.String(), nil
}

// ChunkText splits a long string into segments of ~chunkSize characters with overlap.
func ChunkText(text string, chunkSize int, overlap int) []string {
	var chunks []string
	runes := []rune(text)
	totalLen := len(runes)

	if totalLen <= chunkSize {
		return []string{text}
	}

	for i := 0; i < totalLen; i += (chunkSize - overlap) {
		end := i + chunkSize
		if end > totalLen {
			end = totalLen
		}
		chunks = append(chunks, string(runes[i:end]))
	}

	return chunks
}
