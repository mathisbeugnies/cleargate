package watermark

import (
	"fmt"
	"strconv"
	"strings"
)

// Zero-Width Characters for Steganography
const (
	ZeroWidthSpace     = '\u200B' // Represents '0'
	ZeroWidthNonJoiner = '\u200C' // Represents '1'
	ZeroWidthJoiner    = '\u200D' // Delimiter
)

// Encoder handles text watermarking
type Encoder struct{}

func NewEncoder() *Encoder {
	return &Encoder{}
}

// Encode generates an invisible watermark string containing UserID and Timestamp
func (e *Encoder) Encode(userID string, timestamp int64) string {
	// Convert data to binary strings
	userBin := toBinary(userID)
	timeBin := strconv.FormatInt(timestamp, 2)

	// Build the watermark
	// [DELIM] [USER_BIN] [DELIM] [TIME_BIN] [DELIM]
	var builder strings.Builder
	builder.WriteRune(ZeroWidthJoiner) // Start

	for _, char := range userBin {
		if char == '0' {
			builder.WriteRune(ZeroWidthSpace)
		} else {
			builder.WriteRune(ZeroWidthNonJoiner)
		}
	}

	builder.WriteRune(ZeroWidthJoiner) // Separator

	for _, char := range timeBin {
		if char == '0' {
			builder.WriteRune(ZeroWidthSpace)
		} else {
			builder.WriteRune(ZeroWidthNonJoiner)
		}
	}

	builder.WriteRune(ZeroWidthJoiner) // End

	return builder.String()
}

// Decode extracts the watermark from a text
func (e *Encoder) Decode(text string) (string, int64, error) {
	// Extract the sequence of zero-width characters
	var sequence []rune
	found := false

	for _, char := range text {
		if char == ZeroWidthSpace || char == ZeroWidthNonJoiner || char == ZeroWidthJoiner {
			sequence = append(sequence, char)
			found = true
		}
	}

	if !found || len(sequence) == 0 {
		return "", 0, fmt.Errorf("no watermark found")
	}

	// Reconstruct binary strings
	// Expected format: [JOINER] [BITS...] [JOINER] [BITS...] [JOINER]
	// We might have multiple watermarks if text was pasted multiple times. We verify the LAST valid one or scan.
	// Simplified: Split by JOINER.

	// Convert Runes back to "0", "1", "D" (Delimiter) representation for easier parsing
	var simpler strings.Builder
	for _, r := range sequence {
		switch r {
		case ZeroWidthSpace:
			simpler.WriteRune('0')
		case ZeroWidthNonJoiner:
			simpler.WriteRune('1')
		case ZeroWidthJoiner:
			simpler.WriteRune('D')
		}
	}

	parts := strings.Split(simpler.String(), "D")
	// parts[0] is empty (before first D), parts[1] is User, parts[2] is Time, parts[3] is empty (after last D)
	// We need to find a sequence "D...D...D"

	// Robust search for valid segments
	for i := 0; i < len(parts)-2; i++ {
		userBin := parts[i+1]
		timeBin := parts[i+2]

		if userBin == "" || timeBin == "" {
			continue
		}

		userID := fromBinary(userBin)
		timestamp, err := strconv.ParseInt(timeBin, 2, 64)
		if err == nil && userID != "" {
			return userID, timestamp, nil
		}
	}

	return "", 0, fmt.Errorf("invalid watermark structure")
}

// Helpers
func toBinary(s string) string {
	var bin strings.Builder
	for _, c := range s {
		bin.WriteString(fmt.Sprintf("%08b", c))
	}
	return bin.String()
}

func fromBinary(s string) string {
	var text strings.Builder
	for i := 0; i+8 <= len(s); i += 8 {
		byteVal, _ := strconv.ParseInt(s[i:i+8], 2, 64)
		text.WriteByte(byte(byteVal))
	}
	return text.String()
}
