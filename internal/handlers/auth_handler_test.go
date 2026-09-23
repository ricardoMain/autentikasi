package handlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
	"autentikasi/internal/config"
	"autentikasi/internal/models"
	"autentikasi/internal/services"
)

type mockUserRepo struct{ mock.Mock }

func (m *mockUserRepo) Create(ctx context.Context, user *models.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}
func (m *mockUserRepo) FindByEmail(ctx context.Context, email string) (*models.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}
func (m *mockUserRepo) FindByProvider(ctx context.Context, provider, providerID string) (*models.User, error) {
	args := m.Called(ctx, provider, providerID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}
func (m *mockUserRepo) FindByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}
func (m *mockUserRepo) Update(ctx context.Context, user *models.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

type mockTokenRepo struct{ mock.Mock }

func (m *mockTokenRepo) Create(ctx context.Context, userID uuid.UUID, token string, expiresAt time.Time) (*models.RefreshToken, error) {
	args := m.Called(ctx, userID, token, expiresAt)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.RefreshToken), args.Error(1)
}
func (m *mockTokenRepo) FindByToken(ctx context.Context, token string) (*models.RefreshToken, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.RefreshToken), args.Error(1)
}
func (m *mockTokenRepo) DeleteByToken(ctx context.Context, token string) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}
func (m *mockTokenRepo) DeleteByUserID(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func newTestAuthHandler(userRepo *mockUserRepo, tokenRepo *mockTokenRepo) *AuthHandler {
	cfg := &config.Config{JWTSecret: "test-secret", JWTExpiry: time.Minute, RefreshExpiry: time.Hour}
	tokenSvc := services.NewTokenService(cfg)
	authSvc := services.NewAuthService(userRepo, tokenRepo, tokenSvc, cfg)
	return NewAuthHandler(authSvc)
}

func doRequest(r *gin.Engine, method, path string, body interface{}) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestRegister_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	userRepo := new(mockUserRepo)
	tokenRepo := new(mockTokenRepo)
	userRepo.On("FindByEmail", mock.Anything, "new@example.com").Return(nil, sql.ErrNoRows)
	userRepo.On("Create", mock.Anything, mock.AnythingOfType("*models.User")).Return(nil)
	tokenRepo.On("Create", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(&models.RefreshToken{}, nil)

	h := newTestAuthHandler(userRepo, tokenRepo)
	r := gin.New()
	r.POST("/register", h.Register)

	w := doRequest(r, http.MethodPost, "/register", models.RegisterRequest{
		Email: "new@example.com", Password: "password123", Name: "New User",
	})

	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestRegister_EmailExists(t *testing.T) {
	gin.SetMode(gin.TestMode)
	userRepo := new(mockUserRepo)
	tokenRepo := new(mockTokenRepo)
	userRepo.On("FindByEmail", mock.Anything, "taken@example.com").
		Return(&models.User{Email: "taken@example.com"}, nil)

	h := newTestAuthHandler(userRepo, tokenRepo)
	r := gin.New()
	r.POST("/register", h.Register)

	w := doRequest(r, http.MethodPost, "/register", models.RegisterRequest{
		Email: "taken@example.com", Password: "password123", Name: "Someone",
	})

	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestLogin_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	hashed, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	userRepo := new(mockUserRepo)
	tokenRepo := new(mockTokenRepo)
	userRepo.On("FindByEmail", mock.Anything, "user@example.com").Return(&models.User{
		ID: uuid.New(), Email: "user@example.com", Password: string(hashed), Role: "user",
	}, nil)
	tokenRepo.On("Create", mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(&models.RefreshToken{}, nil)

	h := newTestAuthHandler(userRepo, tokenRepo)
	r := gin.New()
	r.POST("/login", h.Login)

	w := doRequest(r, http.MethodPost, "/login", models.LoginRequest{
		Email: "user@example.com", Password: "password123",
	})

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestLogin_WrongPassword(t *testing.T) {
	gin.SetMode(gin.TestMode)
	hashed, _ := bcrypt.GenerateFromPassword([]byte("correct-password"), bcrypt.DefaultCost)
	userRepo := new(mockUserRepo)
	tokenRepo := new(mockTokenRepo)
	userRepo.On("FindByEmail", mock.Anything, "user@example.com").Return(&models.User{
		ID: uuid.New(), Email: "user@example.com", Password: string(hashed), Role: "user",
	}, nil)

	h := newTestAuthHandler(userRepo, tokenRepo)
	r := gin.New()
	r.POST("/login", h.Login)

	w := doRequest(r, http.MethodPost, "/login", models.LoginRequest{
		Email: "user@example.com", Password: "wrong-password",
	})

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRefresh_InvalidToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	userRepo := new(mockUserRepo)
	tokenRepo := new(mockTokenRepo)
	tokenRepo.On("FindByToken", mock.Anything, "bogus-token").Return(nil, sql.ErrNoRows)

	h := newTestAuthHandler(userRepo, tokenRepo)
	r := gin.New()
	r.POST("/refresh", h.Refresh)

	w := doRequest(r, http.MethodPost, "/refresh", models.RefreshRequest{RefreshToken: "bogus-token"})

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
