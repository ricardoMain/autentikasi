package services

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"autentikasi/internal/config"
)

func TestValidateAccessToken_RoundTrip(t *testing.T) {
	svc := NewTokenService(&config.Config{JWTSecret: "test-secret", JWTExpiry: time.Minute})
	userID := uuid.New()

	token, err := svc.GenerateAccessToken(userID, "user@example.com", "admin")
	assert.NoError(t, err)

	claims, err := svc.ValidateAccessToken(token)
	assert.NoError(t, err)
	assert.Equal(t, userID, claims.UserID)
	assert.Equal(t, "admin", claims.Role)
}

// Regression test for alg-confusion: a token signed with "none" must never
// be accepted just because the secret-based verifier is skipped for it.
func TestValidateAccessToken_RejectsNoneAlg(t *testing.T) {
	svc := NewTokenService(&config.Config{JWTSecret: "test-secret", JWTExpiry: time.Minute})

	claims := TokenClaims{
		UserID: uuid.New(),
		Email:  "attacker@example.com",
		Role:   "admin",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	forged, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	assert.NoError(t, err)

	_, err = svc.ValidateAccessToken(forged)
	assert.Error(t, err)
}
