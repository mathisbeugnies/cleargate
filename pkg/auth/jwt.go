package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog/log"
)

// SecretKey signs session JWTs. Set it via JWT_SECRET in production. If it's
// missing we generate a random one per process rather than ship a hardcoded
// fallback, so a misconfigured deploy just loses sessions on restart.
var SecretKey = loadSecretKey()

func loadSecretKey() []byte {
	if v := os.Getenv("JWT_SECRET"); v != "" {
		return []byte(v)
	}

	log.Warn().Msg("JWT_SECRET not set, generating a random secret for this process. Set JWT_SECRET in production.")

	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		log.Fatal().Err(err).Msg("Failed to generate a random JWT secret")
	}
	return []byte(hex.EncodeToString(buf))
}

type Claims struct {
	UserID int    `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	OrgID  int    `json:"org_id"`
	jwt.RegisteredClaims
}

func GenerateToken(userID int, email, role string, orgID int) (string, error) {
	claims := &Claims{
		UserID: userID,
		Email:  email,
		Role:   role,
		OrgID:  orgID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(8 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(SecretKey)
}

func ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return SecretKey, nil
	}, jwt.WithValidMethods([]string{"HS256"}))

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}
