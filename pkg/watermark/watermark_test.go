package watermark

import (
	"testing"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	e := NewEncoder()
	const user = "user-42"
	const ts int64 = 1_700_123_456

	visible := "Here is the assistant's answer."
	marked := visible + e.Encode(user, ts)

	// The watermark must be invisible: the printable text is unchanged.
	stripped := ""
	for _, r := range marked {
		if r != ZeroWidthSpace && r != ZeroWidthNonJoiner && r != ZeroWidthJoiner {
			stripped += string(r)
		}
	}
	if stripped != visible {
		t.Fatalf("watermark altered visible text: %q", stripped)
	}

	gotUser, gotTS, err := e.Decode(marked)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if gotUser != user {
		t.Errorf("user: got %q want %q", gotUser, user)
	}
	if gotTS != ts {
		t.Errorf("timestamp: got %d want %d", gotTS, ts)
	}
}

func TestDecodeNoWatermark(t *testing.T) {
	e := NewEncoder()
	if _, _, err := e.Decode("plain text, nothing hidden"); err == nil {
		t.Fatal("expected an error when no watermark is present")
	}
}
