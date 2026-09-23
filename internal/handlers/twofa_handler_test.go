package handlers

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
	"autentikasi/internal/config"
	"autentikasi/internal/models"
	"autentikasi/internal/services"
)

func newTestTwoFAHandler(userRepo *mockUserRepo, tokenRepo *mockTokenRepo) (*TwoFAHandler, *AuthHandler) {
	cfg := &config.Config{JWTSecret: "test-secret", JWTExpiry: time.Minute, RefreshExpiry: time.Hour}
	tokenSvc := services.NewTokenService(cfg)
	emailSvc := services.NewEmailService(cfg)
	totpSvc := services.NewTOTPService("test")
	authSvc := services.NewAuthService(userRepo, tokenRepo, new(mockOrgRepo), new(mockVerifyRepo), tokenSvc, emailSvc, totpSvc, cfg)
	return NewTwoFAHandler(authSvc), NewAuthHandler(authSvc)
}

func withUserID(userID string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("user_id", userID)
		c.Next()
	}
}

func TestTwoFA_SetupThenConfirm(t *testing.T) {
	gin.SetMode(gin.TestMode)
	userID := uuid.New()
	userRepo := new(mockUserRepo)
	tokenRepo := new(mockTokenRepo)
	user := &models.User{ID: userID, Email: "user@example.com"}
	userRepo.On("FindByID", mock.Anything, userID).Return(user, nil)
	userRepo.On("Update", mock.Anything, mock.Anything).Return(nil)

	h, _ := newTestTwoFAHandler(userRepo, tokenRepo)
	r := gin.New()
	r.Use(withUserID(userID.String()))
	r.POST("/2fa/setup", h.Setup)
	r.POST("/2fa/confirm", h.Confirm)

	w := doRequest(r, http.MethodPost, "/2fa/setup", nil)
	assert.Equal(t, http.StatusOK, w.Code)

	var setupResp struct {
		Data struct {
			Secret string `json:"secret"`
		} `json:"data"`
	}
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &setupResp))
	assert.NotEmpty(t, setupResp.Data.Secret)

	// user.TOTPSecret was mutated in place by the Update mock's captured arg
	code, err := totp.GenerateCode(user.TOTPSecret, time.Now())
	assert.NoError(t, err)

	w = doRequest(r, http.MethodPost, "/2fa/confirm", models.TwoFACodeRequest{Code: code})
	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, user.TOTPEnabled)
}

func TestTwoFA_LoginFlow(t *testing.T) {
	gin.SetMode(gin.TestMode)
	userID := uuid.New()
	secret := "JBSWY3DPEHPK3PXP"
	hashed, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	user := &models.User{
		ID: userID, Email: "user@example.com", Password: string(hashed),
		Role: "user", TOTPEnabled: true, TOTPSecret: secret,
	}

	userRepo := new(mockUserRepo)
	tokenRepo := new(mockTokenRepo)
	userRepo.On("FindByEmail", mock.Anything, "user@example.com").Return(user, nil)
	userRepo.On("FindByID", mock.Anything, userID).Return(user, nil)
	tokenRepo.On("Create", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(&models.RefreshToken{}, nil)

	twoFAHandler, authHandler := newTestTwoFAHandler(userRepo, tokenRepo)
	r := gin.New()
	r.POST("/login", authHandler.Login)
	r.POST("/2fa/login", twoFAHandler.Login)

	w := doRequest(r, http.MethodPost, "/login", models.LoginRequest{Email: "user@example.com", Password: "password123"})
	assert.Equal(t, http.StatusOK, w.Code)

	var loginResp struct {
		Data models.AuthResponse `json:"data"`
	}
	assert.NoError(t, json.Unmarshal(w.Body.Bytes(), &loginResp))
	assert.True(t, loginResp.Data.Requires2FA)
	assert.NotEmpty(t, loginResp.Data.TempToken)

	code, err := totp.GenerateCode(secret, time.Now())
	assert.NoError(t, err)

	w = doRequest(r, http.MethodPost, "/2fa/login", models.TwoFALoginRequest{
		TempToken: loginResp.Data.TempToken, Code: code,
	})
	assert.Equal(t, http.StatusOK, w.Code)
}
