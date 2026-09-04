package integrity

import (
	"testing"
	"time"
)

func sample() LogData {
	return LogData{
		Timestamp:     time.Unix(1_700_000_000, 0).UTC(),
		UserID:        "user-1",
		RequestID:     "req-abc",
		Verdict:       "PASS",
		ThreatDetails: "",
		RiskScore:     0,
	}
}

func TestCalculateHashIsDeterministic(t *testing.T) {
	a := CalculateHash(GenesisHash, sample())
	b := CalculateHash(GenesisHash, sample())
	if a != b {
		t.Fatalf("hash not deterministic: %s vs %s", a, b)
	}
	if len(a) != 64 {
		t.Fatalf("expected 64 hex chars, got %d", len(a))
	}
}

func TestCalculateHashChangesWithData(t *testing.T) {
	base := CalculateHash(GenesisHash, sample())

	tampered := sample()
	tampered.Verdict = "BLOCK"
	if CalculateHash(GenesisHash, tampered) == base {
		t.Fatal("changing verdict must change the hash")
	}

	if CalculateHash("some-other-prev-hash", sample()) == base {
		t.Fatal("changing the previous hash must change the hash")
	}
}

func TestChainDetectsMiddleTampering(t *testing.T) {
	e1 := sample()
	e2 := sample()
	e2.RequestID = "req-2"
	e3 := sample()
	e3.RequestID = "req-3"

	h1 := CalculateHash(GenesisHash, e1)
	h2 := CalculateHash(h1, e2)
	h3 := CalculateHash(h2, e3)

	// Recompute the chain as a verifier would, but with e2 altered.
	e2.Verdict = "BLOCK"
	v1 := CalculateHash(GenesisHash, e1)
	v2 := CalculateHash(v1, e2)
	v3 := CalculateHash(v2, e3)

	if v2 == h2 || v3 == h3 {
		t.Fatal("a tampered middle entry should break every subsequent hash")
	}
}
