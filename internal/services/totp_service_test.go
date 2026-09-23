package services

import (
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
)

func TestTOTPService_RoundTrip(t *testing.T) {
	svc := NewTOTPService("test-issuer")

	secret, uri, err := svc.GenerateSecret("user@example.com")
	assert.NoError(t, err)
	assert.NotEmpty(t, secret)
	assert.Contains(t, uri, "otpauth://")

	code, err := totp.GenerateCode(secret, time.Now())
	assert.NoError(t, err)

	assert.True(t, svc.ValidateCode(secret, code))
	assert.False(t, svc.ValidateCode(secret, "000000"))
}
