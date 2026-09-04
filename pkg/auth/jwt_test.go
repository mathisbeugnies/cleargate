package auth

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestGenerateAndValidateRoundTrip(t *testing.T) {
	tok, err := GenerateToken(7, "a@b.com", "org_admin", 3)
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	claims, err := ValidateToken(tok)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if claims.UserID != 7 || claims.Role != "org_admin" || claims.OrgID != 3 {
		t.Fatalf("claims round-trip mismatch: %+v", claims)
	}
}

func TestValidateTokenRejectsNoneAlg(t *testing.T) {
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, &Claims{UserID: 1, Role: "super_admin"})
	signed, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none: %v", err)
	}
	if _, err := ValidateToken(signed); err == nil {
		t.Fatal("expected 'alg: none' token to be rejected")
	}
}

func TestValidateTokenRejectsWrongSecret(t *testing.T) {
	other := jwt.NewWithClaims(jwt.SigningMethodHS256, &Claims{UserID: 1})
	signed, _ := other.SignedString([]byte("not-the-real-secret-value-here"))
	if _, err := ValidateToken(signed); err == nil {
		t.Fatal("expected token signed with a different secret to be rejected")
	}
}
