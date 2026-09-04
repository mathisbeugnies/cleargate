package mail

import (
	"strings"
	"testing"
)

func TestHeaderSafeStripsCRLF(t *testing.T) {
	in := "victim@example.com\r\nBcc: attacker@evil.com\nSubject: injected"
	out := headerSafe(in)
	if strings.ContainsAny(out, "\r\n") {
		t.Fatalf("headerSafe left a line break in: %q", out)
	}
	if strings.Contains(out, "Bcc:") == false {
		// the text is flattened, not removed; the point is it can't be a new header line
		t.Log("flattened value:", out)
	}
}
