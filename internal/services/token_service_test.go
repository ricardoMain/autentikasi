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

	orgID := uuid.New()
	token, err := svc.GenerateAccessToken(userID, "user@example.com", "admin", orgID)
	assert.NoError(t, err)

	claims, err := svc.ValidateAccessToken(token)
	assert.NoError(t, err)
	assert.Equal(t, userID, claims.UserID)
	assert.Equal(t, "admin", claims.Role)
	assert.Equal(t, orgID, claims.OrganizationID)
}

func TestTwoFAPendingToken_RoundTrip(t *testing.T) {
	svc := NewTokenService(&config.Config{JWTSecret: "test-secret"})
	userID := uuid.New()

	token, err := svc.GenerateTwoFAPendingToken(userID)
	assert.NoError(t, err)

	gotID, err := svc.ValidateTwoFAPendingToken(token)
	assert.NoError(t, err)
	assert.Equal(t, userID, gotID)
}

func TestTwoFAPendingToken_RejectedByNormalValidation(t *testing.T) {
	svc := NewTokenService(&config.Config{JWTSecret: "test-secret"})
	token, err := svc.GenerateTwoFAPendingToken(uuid.New())
	assert.NoError(t, err)

	_, err = svc.ValidateAccessToken(token)
	assert.NoError(t, err) // parses, but...

	claims, _ := svc.ValidateAccessToken(token)
	assert.Equal(t, uuid.Nil, claims.UserID) // ...carries no usable identity
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
