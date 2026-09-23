package services

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
	"autentikasi/internal/config"
	"autentikasi/internal/models"
)

// MockUserRepository mocks UserRepositoryInterface
type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) Create(ctx context.Context, user *models.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockUserRepository) FindByEmail(ctx context.Context, email string) (*models.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) FindByProvider(ctx context.Context, provider, providerID string) (*models.User, error) {
	args := m.Called(ctx, provider, providerID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) FindByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserRepository) Update(ctx context.Context, user *models.User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

// MockTokenRepository mocks TokenRepositoryInterface
type MockTokenRepository struct {
	mock.Mock
}

func (m *MockTokenRepository) Create(ctx context.Context, userID uuid.UUID, token string, expiresAt time.Time) (*models.RefreshToken, error) {
	args := m.Called(ctx, userID, token, expiresAt)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.RefreshToken), args.Error(1)
}

func (m *MockTokenRepository) FindByToken(ctx context.Context, token string) (*models.RefreshToken, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.RefreshToken), args.Error(1)
}

func (m *MockTokenRepository) DeleteByToken(ctx context.Context, token string) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

func (m *MockTokenRepository) DeleteByUserID(ctx context.Context, userID uuid.UUID) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

// Helper function to create test config
func getTestConfig() *config.Config {
	return &config.Config{
		ServerPort:    "8080",
		JWTSecret:     "test-secret-key-very-long-for-testing",
		RefreshExpiry: 24 * time.Hour,
		SecureCookie:  false,
	}
}

// Helper function to hash password
func hashPassword(password string) string {
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hashedPassword)
}

// TestRegisterSuccess tests successful user registration
func TestRegisterSuccess(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockTokenRepo := new(MockTokenRepository)
	tokenSvc := NewTokenService(getTestConfig())

	// Mock: user doesn't exist
	mockUserRepo.On("FindByEmail", mock.Anything, "test@example.com").Return(nil, sql.ErrNoRows)

	// Mock: create user
	mockUserRepo.On("Create", mock.Anything, mock.MatchedBy(func(u *models.User) bool {
		return u.Email == "test@example.com" && u.Name == "Test User" && u.Role == "user"
	})).Run(func(args mock.Arguments) {
		user := args.Get(1).(*models.User)
		user.ID = uuid.New()
		user.CreatedAt = time.Now()
		user.UpdatedAt = time.Now()
	}).Return(nil)

	// Mock: create refresh token
	mockTokenRepo.On("Create", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
		&models.RefreshToken{
			ID:        uuid.New(),
			Token:     "test-refresh-token",
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}, nil)

	authSvc := NewAuthService(mockUserRepo, mockTokenRepo, tokenSvc, getTestConfig())

	req := models.RegisterRequest{
		Email:    "test@example.com",
		Password: "SecurePassword123!",
		Name:     "Test User",
	}

	resp, err := authSvc.Register(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "test@example.com", resp.User.Email)
	assert.Equal(t, "Test User", resp.User.Name)
	assert.Equal(t, "user", resp.User.Role)
	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken)

	mockUserRepo.AssertExpectations(t)
	mockTokenRepo.AssertExpectations(t)
}

// TestRegisterEmailAlreadyExists tests registration with existing email
func TestRegisterEmailAlreadyExists(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockTokenRepo := new(MockTokenRepository)
	tokenSvc := NewTokenService(getTestConfig())

	existingUser := &models.User{
		ID:    uuid.New(),
		Email: "test@example.com",
		Name:  "Existing User",
	}

	// Mock: user already exists
	mockUserRepo.On("FindByEmail", mock.Anything, "test@example.com").Return(existingUser, nil)

	authSvc := NewAuthService(mockUserRepo, mockTokenRepo, tokenSvc, getTestConfig())

	req := models.RegisterRequest{
		Email:    "test@example.com",
		Password: "SecurePassword123!",
		Name:     "Test User",
	}

	resp, err := authSvc.Register(context.Background(), req)

	assert.Error(t, err)
	assert.Equal(t, ErrEmailAlreadyExists, err)
	assert.Nil(t, resp)

	mockUserRepo.AssertExpectations(t)
}

// TestLoginSuccess tests successful login
func TestLoginSuccess(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockTokenRepo := new(MockTokenRepository)
	tokenSvc := NewTokenService(getTestConfig())

	hashedPassword := hashPassword("SecurePassword123!")
	user := &models.User{
		ID:       uuid.New(),
		Email:    "test@example.com",
		Password: hashedPassword,
		Name:     "Test User",
		Role:     "user",
	}

	// Mock: find user
	mockUserRepo.On("FindByEmail", mock.Anything, "test@example.com").Return(user, nil)

	// Mock: create refresh token
	mockTokenRepo.On("Create", mock.Anything, user.ID, mock.Anything, mock.Anything).Return(
		&models.RefreshToken{
			ID:        uuid.New(),
			Token:     "test-refresh-token",
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}, nil)

	authSvc := NewAuthService(mockUserRepo, mockTokenRepo, tokenSvc, getTestConfig())

	req := models.LoginRequest{
		Email:    "test@example.com",
		Password: "SecurePassword123!",
	}

	resp, err := authSvc.Login(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "test@example.com", resp.User.Email)
	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken)

	mockUserRepo.AssertExpectations(t)
	mockTokenRepo.AssertExpectations(t)
}

// TestLoginUserNotFound tests login with non-existent user
func TestLoginUserNotFound(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockTokenRepo := new(MockTokenRepository)
	tokenSvc := NewTokenService(getTestConfig())

	// Mock: user not found
	mockUserRepo.On("FindByEmail", mock.Anything, "test@example.com").Return(nil, sql.ErrNoRows)

	authSvc := NewAuthService(mockUserRepo, mockTokenRepo, tokenSvc, getTestConfig())

	req := models.LoginRequest{
		Email:    "test@example.com",
		Password: "SecurePassword123!",
	}

	resp, err := authSvc.Login(context.Background(), req)

	assert.Error(t, err)
	assert.Equal(t, ErrInvalidCredentials, err)
	assert.Nil(t, resp)

	mockUserRepo.AssertExpectations(t)
}

// TestLoginInvalidPassword tests login with wrong password
func TestLoginInvalidPassword(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockTokenRepo := new(MockTokenRepository)
	tokenSvc := NewTokenService(getTestConfig())

	hashedPassword := hashPassword("SecurePassword123!")
	user := &models.User{
		ID:       uuid.New(),
		Email:    "test@example.com",
		Password: hashedPassword,
		Name:     "Test User",
		Role:     "user",
	}

	// Mock: find user
	mockUserRepo.On("FindByEmail", mock.Anything, "test@example.com").Return(user, nil)

	authSvc := NewAuthService(mockUserRepo, mockTokenRepo, tokenSvc, getTestConfig())

	req := models.LoginRequest{
		Email:    "test@example.com",
		Password: "WrongPassword!",
	}

	resp, err := authSvc.Login(context.Background(), req)

	assert.Error(t, err)
	assert.Equal(t, ErrInvalidCredentials, err)
	assert.Nil(t, resp)

	mockUserRepo.AssertExpectations(t)
}

// TestRefreshSuccess tests successful token refresh
func TestRefreshSuccess(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockTokenRepo := new(MockTokenRepository)
	tokenSvc := NewTokenService(getTestConfig())

	userID := uuid.New()
	user := &models.User{
		ID:    userID,
		Email: "test@example.com",
		Name:  "Test User",
		Role:  "user",
	}

	refreshToken := "test-refresh-token"
	storedToken := &models.RefreshToken{
		ID:        uuid.New(),
		UserID:    userID,
		Token:     refreshToken,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	// Mock: find refresh token
	mockTokenRepo.On("FindByToken", mock.Anything, refreshToken).Return(storedToken, nil)

	// Mock: find user
	mockUserRepo.On("FindByID", mock.Anything, userID).Return(user, nil)

	// Mock: delete old token
	mockTokenRepo.On("DeleteByToken", mock.Anything, refreshToken).Return(nil)

	// Mock: create new refresh token
	mockTokenRepo.On("Create", mock.Anything, userID, mock.Anything, mock.Anything).Return(
		&models.RefreshToken{
			ID:        uuid.New(),
			Token:     "new-refresh-token",
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}, nil)

	authSvc := NewAuthService(mockUserRepo, mockTokenRepo, tokenSvc, getTestConfig())

	resp, err := authSvc.Refresh(context.Background(), refreshToken)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "test@example.com", resp.User.Email)
	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken)

	mockUserRepo.AssertExpectations(t)
	mockTokenRepo.AssertExpectations(t)
}

// TestRefreshTokenExpired tests refresh with expired token
func TestRefreshTokenExpired(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockTokenRepo := new(MockTokenRepository)
	tokenSvc := NewTokenService(getTestConfig())

	userID := uuid.New()
	refreshToken := "test-refresh-token"
	storedToken := &models.RefreshToken{
		ID:        uuid.New(),
		UserID:    userID,
		Token:     refreshToken,
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired
	}

	// Mock: find expired refresh token
	mockTokenRepo.On("FindByToken", mock.Anything, refreshToken).Return(storedToken, nil)

	// Mock: delete expired token
	mockTokenRepo.On("DeleteByToken", mock.Anything, refreshToken).Return(nil)

	authSvc := NewAuthService(mockUserRepo, mockTokenRepo, tokenSvc, getTestConfig())

	resp, err := authSvc.Refresh(context.Background(), refreshToken)

	assert.Error(t, err)
	assert.Equal(t, ErrInvalidToken, err)
	assert.Nil(t, resp)

	mockTokenRepo.AssertExpectations(t)
}

// TestRefreshTokenNotFound tests refresh with non-existent token
func TestRefreshTokenNotFound(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockTokenRepo := new(MockTokenRepository)
	tokenSvc := NewTokenService(getTestConfig())

	// Mock: token not found
	mockTokenRepo.On("FindByToken", mock.Anything, "invalid-token").Return(nil, sql.ErrNoRows)

	authSvc := NewAuthService(mockUserRepo, mockTokenRepo, tokenSvc, getTestConfig())

	resp, err := authSvc.Refresh(context.Background(), "invalid-token")

	assert.Error(t, err)
	assert.Equal(t, ErrInvalidToken, err)
	assert.Nil(t, resp)

	mockTokenRepo.AssertExpectations(t)
}

// TestLogoutSuccess tests successful logout
func TestLogoutSuccess(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockTokenRepo := new(MockTokenRepository)
	tokenSvc := NewTokenService(getTestConfig())

	refreshToken := "test-refresh-token"

	// Mock: delete token
	mockTokenRepo.On("DeleteByToken", mock.Anything, refreshToken).Return(nil)

	authSvc := NewAuthService(mockUserRepo, mockTokenRepo, tokenSvc, getTestConfig())

	err := authSvc.Logout(context.Background(), refreshToken)

	assert.NoError(t, err)

	mockTokenRepo.AssertExpectations(t)
}

// TestLogoutError tests logout with delete error
func TestLogoutError(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockTokenRepo := new(MockTokenRepository)
	tokenSvc := NewTokenService(getTestConfig())

	refreshToken := "test-refresh-token"

	// Mock: delete fails
	mockTokenRepo.On("DeleteByToken", mock.Anything, refreshToken).Return(errors.New("database error"))

	authSvc := NewAuthService(mockUserRepo, mockTokenRepo, tokenSvc, getTestConfig())

	err := authSvc.Logout(context.Background(), refreshToken)

	assert.Error(t, err)

	mockTokenRepo.AssertExpectations(t)
}

// TestGetProfileSuccess tests successful profile retrieval
func TestGetProfileSuccess(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockTokenRepo := new(MockTokenRepository)
	tokenSvc := NewTokenService(getTestConfig())

	userID := uuid.New()
	user := &models.User{
		ID:    userID,
		Email: "test@example.com",
		Name:  "Test User",
		Role:  "user",
	}

	// Mock: find user
	mockUserRepo.On("FindByID", mock.Anything, userID).Return(user, nil)

	authSvc := NewAuthService(mockUserRepo, mockTokenRepo, tokenSvc, getTestConfig())

	profile, err := authSvc.GetProfile(context.Background(), userID.String())

	assert.NoError(t, err)
	assert.NotNil(t, profile)
	assert.Equal(t, "test@example.com", profile.Email)
	assert.Equal(t, "Test User", profile.Name)

	mockUserRepo.AssertExpectations(t)
}

// TestGetProfileUserNotFound tests profile retrieval for non-existent user
func TestGetProfileUserNotFound(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockTokenRepo := new(MockTokenRepository)
	tokenSvc := NewTokenService(getTestConfig())

	userID := uuid.New()

	// Mock: user not found
	mockUserRepo.On("FindByID", mock.Anything, userID).Return(nil, sql.ErrNoRows)

	authSvc := NewAuthService(mockUserRepo, mockTokenRepo, tokenSvc, getTestConfig())

	profile, err := authSvc.GetProfile(context.Background(), userID.String())

	assert.Error(t, err)
	assert.Equal(t, ErrUserNotFound, err)
	assert.Nil(t, profile)

	mockUserRepo.AssertExpectations(t)
}

// TestGetProfileInvalidUUID tests profile retrieval with invalid UUID
func TestGetProfileInvalidUUID(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockTokenRepo := new(MockTokenRepository)
	tokenSvc := NewTokenService(getTestConfig())

	authSvc := NewAuthService(mockUserRepo, mockTokenRepo, tokenSvc, getTestConfig())

	profile, err := authSvc.GetProfile(context.Background(), "invalid-uuid")

	assert.Error(t, err)
	assert.Nil(t, profile)
}
