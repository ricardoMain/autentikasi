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

// MockOrganizationRepository mocks OrganizationRepositoryInterface
type MockOrganizationRepository struct {
	mock.Mock
}

func (m *MockOrganizationRepository) Create(ctx context.Context, org *models.Organization) error {
	args := m.Called(ctx, org)
	return args.Error(0)
}

func (m *MockOrganizationRepository) FindByID(ctx context.Context, id uuid.UUID) (*models.Organization, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.Organization), args.Error(1)
}

// MockVerificationTokenRepository mocks VerificationTokenRepositoryInterface
type MockVerificationTokenRepository struct {
	mock.Mock
}

func (m *MockVerificationTokenRepository) Create(ctx context.Context, userID uuid.UUID, token, purpose string, expiresAt time.Time) (*models.VerificationToken, error) {
	args := m.Called(ctx, userID, token, purpose, expiresAt)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.VerificationToken), args.Error(1)
}

func (m *MockVerificationTokenRepository) FindByToken(ctx context.Context, token string) (*models.VerificationToken, error) {
	args := m.Called(ctx, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.VerificationToken), args.Error(1)
}

func (m *MockVerificationTokenRepository) DeleteByToken(ctx context.Context, token string) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

// testDeps bundles the mocks a test needs; only stub what that test exercises.
type testDeps struct {
	userRepo   *MockUserRepository
	tokenRepo  *MockTokenRepository
	orgRepo    *MockOrganizationRepository
	verifyRepo *MockVerificationTokenRepository
}

func newTestDeps() testDeps {
	return testDeps{
		userRepo:   new(MockUserRepository),
		tokenRepo:  new(MockTokenRepository),
		orgRepo:    new(MockOrganizationRepository),
		verifyRepo: new(MockVerificationTokenRepository),
	}
}

func newTestAuthService(d testDeps) *AuthService {
	cfg := getTestConfig()
	return NewAuthService(d.userRepo, d.tokenRepo, d.orgRepo, d.verifyRepo,
		NewTokenService(cfg), NewEmailService(cfg), NewTOTPService("test"), cfg)
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

// stubOrgAndVerification sets up the mocks Register needs beyond the user:
// creating the organization and best-effort sending a verification email.
func stubOrgAndVerification(d testDeps) {
	d.orgRepo.On("Create", mock.Anything, mock.AnythingOfType("*models.Organization")).Run(func(args mock.Arguments) {
		org := args.Get(1).(*models.Organization)
		org.ID = uuid.New()
	}).Return(nil)
	d.verifyRepo.On("Create", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(&models.VerificationToken{}, nil)
}

// TestRegisterSuccess tests successful user registration
func TestRegisterSuccess(t *testing.T) {
	d := newTestDeps()
	stubOrgAndVerification(d)

	d.userRepo.On("FindByEmail", mock.Anything, "test@example.com").Return(nil, sql.ErrNoRows)

	d.userRepo.On("Create", mock.Anything, mock.MatchedBy(func(u *models.User) bool {
		return u.Email == "test@example.com" && u.Name == "Test User" && u.Role == "user"
	})).Run(func(args mock.Arguments) {
		user := args.Get(1).(*models.User)
		user.ID = uuid.New()
		user.CreatedAt = time.Now()
		user.UpdatedAt = time.Now()
	}).Return(nil)

	d.tokenRepo.On("Create", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
		&models.RefreshToken{
			ID:        uuid.New(),
			Token:     "test-refresh-token",
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}, nil)

	authSvc := newTestAuthService(d)

	req := models.RegisterRequest{
		Email:            "test@example.com",
		Password:         "SecurePassword123!",
		Name:             "Test User",
		OrganizationName: "Test Org",
	}

	resp, err := authSvc.Register(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "test@example.com", resp.User.Email)
	assert.Equal(t, "Test User", resp.User.Name)
	assert.Equal(t, "user", resp.User.Role)
	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken)

	d.userRepo.AssertExpectations(t)
	d.tokenRepo.AssertExpectations(t)
	d.orgRepo.AssertExpectations(t)
}

// TestRegisterEmailAlreadyExists tests registration with existing email
func TestRegisterEmailAlreadyExists(t *testing.T) {
	d := newTestDeps()

	existingUser := &models.User{
		ID:    uuid.New(),
		Email: "test@example.com",
		Name:  "Existing User",
	}

	d.userRepo.On("FindByEmail", mock.Anything, "test@example.com").Return(existingUser, nil)

	authSvc := newTestAuthService(d)

	req := models.RegisterRequest{
		Email:            "test@example.com",
		Password:         "SecurePassword123!",
		Name:             "Test User",
		OrganizationName: "Test Org",
	}

	resp, err := authSvc.Register(context.Background(), req)

	assert.Error(t, err)
	assert.Equal(t, ErrEmailAlreadyExists, err)
	assert.Nil(t, resp)

	d.userRepo.AssertExpectations(t)
}

// TestLoginSuccess tests successful login
func TestLoginSuccess(t *testing.T) {
	d := newTestDeps()

	hashedPassword := hashPassword("SecurePassword123!")
	user := &models.User{
		ID:       uuid.New(),
		Email:    "test@example.com",
		Password: hashedPassword,
		Name:     "Test User",
		Role:     "user",
	}

	d.userRepo.On("FindByEmail", mock.Anything, "test@example.com").Return(user, nil)

	d.tokenRepo.On("Create", mock.Anything, user.ID, mock.Anything, mock.Anything).Return(
		&models.RefreshToken{
			ID:        uuid.New(),
			Token:     "test-refresh-token",
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}, nil)

	authSvc := newTestAuthService(d)

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

	d.userRepo.AssertExpectations(t)
	d.tokenRepo.AssertExpectations(t)
}

// TestLoginRequires2FA tests that login pauses for TOTP when enabled
func TestLoginRequires2FA(t *testing.T) {
	d := newTestDeps()

	hashedPassword := hashPassword("SecurePassword123!")
	user := &models.User{
		ID:          uuid.New(),
		Email:       "test@example.com",
		Password:    hashedPassword,
		Name:        "Test User",
		Role:        "user",
		TOTPEnabled: true,
		TOTPSecret:  "JBSWY3DPEHPK3PXP",
	}

	d.userRepo.On("FindByEmail", mock.Anything, "test@example.com").Return(user, nil)

	authSvc := newTestAuthService(d)

	req := models.LoginRequest{Email: "test@example.com", Password: "SecurePassword123!"}
	resp, err := authSvc.Login(context.Background(), req)

	assert.NoError(t, err)
	assert.True(t, resp.Requires2FA)
	assert.NotEmpty(t, resp.TempToken)
	assert.Empty(t, resp.AccessToken)

	d.userRepo.AssertExpectations(t)
	d.tokenRepo.AssertExpectations(t) // no Create expected
}

// TestLoginUserNotFound tests login with non-existent user
func TestLoginUserNotFound(t *testing.T) {
	d := newTestDeps()

	d.userRepo.On("FindByEmail", mock.Anything, "test@example.com").Return(nil, sql.ErrNoRows)

	authSvc := newTestAuthService(d)

	req := models.LoginRequest{
		Email:    "test@example.com",
		Password: "SecurePassword123!",
	}

	resp, err := authSvc.Login(context.Background(), req)

	assert.Error(t, err)
	assert.Equal(t, ErrInvalidCredentials, err)
	assert.Nil(t, resp)

	d.userRepo.AssertExpectations(t)
}

// TestLoginInvalidPassword tests login with wrong password
func TestLoginInvalidPassword(t *testing.T) {
	d := newTestDeps()

	hashedPassword := hashPassword("SecurePassword123!")
	user := &models.User{
		ID:       uuid.New(),
		Email:    "test@example.com",
		Password: hashedPassword,
		Name:     "Test User",
		Role:     "user",
	}

	d.userRepo.On("FindByEmail", mock.Anything, "test@example.com").Return(user, nil)

	authSvc := newTestAuthService(d)

	req := models.LoginRequest{
		Email:    "test@example.com",
		Password: "WrongPassword!",
	}

	resp, err := authSvc.Login(context.Background(), req)

	assert.Error(t, err)
	assert.Equal(t, ErrInvalidCredentials, err)
	assert.Nil(t, resp)

	d.userRepo.AssertExpectations(t)
}

// TestRefreshSuccess tests successful token refresh
func TestRefreshSuccess(t *testing.T) {
	d := newTestDeps()

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

	d.tokenRepo.On("FindByToken", mock.Anything, refreshToken).Return(storedToken, nil)
	d.userRepo.On("FindByID", mock.Anything, userID).Return(user, nil)
	d.tokenRepo.On("DeleteByToken", mock.Anything, refreshToken).Return(nil)
	d.tokenRepo.On("Create", mock.Anything, userID, mock.Anything, mock.Anything).Return(
		&models.RefreshToken{
			ID:        uuid.New(),
			Token:     "new-refresh-token",
			ExpiresAt: time.Now().Add(24 * time.Hour),
		}, nil)

	authSvc := newTestAuthService(d)

	resp, err := authSvc.Refresh(context.Background(), refreshToken)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "test@example.com", resp.User.Email)
	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken)

	d.userRepo.AssertExpectations(t)
	d.tokenRepo.AssertExpectations(t)
}

// TestRefreshTokenExpired tests refresh with expired token
func TestRefreshTokenExpired(t *testing.T) {
	d := newTestDeps()

	userID := uuid.New()
	refreshToken := "test-refresh-token"
	storedToken := &models.RefreshToken{
		ID:        uuid.New(),
		UserID:    userID,
		Token:     refreshToken,
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired
	}

	d.tokenRepo.On("FindByToken", mock.Anything, refreshToken).Return(storedToken, nil)
	d.tokenRepo.On("DeleteByToken", mock.Anything, refreshToken).Return(nil)

	authSvc := newTestAuthService(d)

	resp, err := authSvc.Refresh(context.Background(), refreshToken)

	assert.Error(t, err)
	assert.Equal(t, ErrInvalidToken, err)
	assert.Nil(t, resp)

	d.tokenRepo.AssertExpectations(t)
}

// TestRefreshTokenNotFound tests refresh with non-existent token
func TestRefreshTokenNotFound(t *testing.T) {
	d := newTestDeps()

	d.tokenRepo.On("FindByToken", mock.Anything, "invalid-token").Return(nil, sql.ErrNoRows)

	authSvc := newTestAuthService(d)

	resp, err := authSvc.Refresh(context.Background(), "invalid-token")

	assert.Error(t, err)
	assert.Equal(t, ErrInvalidToken, err)
	assert.Nil(t, resp)

	d.tokenRepo.AssertExpectations(t)
}

// TestLogoutSuccess tests successful logout
func TestLogoutSuccess(t *testing.T) {
	d := newTestDeps()

	refreshToken := "test-refresh-token"
	d.tokenRepo.On("DeleteByToken", mock.Anything, refreshToken).Return(nil)

	authSvc := newTestAuthService(d)

	err := authSvc.Logout(context.Background(), refreshToken)

	assert.NoError(t, err)

	d.tokenRepo.AssertExpectations(t)
}

// TestLogoutError tests logout with delete error
func TestLogoutError(t *testing.T) {
	d := newTestDeps()

	refreshToken := "test-refresh-token"
	d.tokenRepo.On("DeleteByToken", mock.Anything, refreshToken).Return(errors.New("database error"))

	authSvc := newTestAuthService(d)

	err := authSvc.Logout(context.Background(), refreshToken)

	assert.Error(t, err)

	d.tokenRepo.AssertExpectations(t)
}

// TestGetProfileSuccess tests successful profile retrieval
func TestGetProfileSuccess(t *testing.T) {
	d := newTestDeps()

	userID := uuid.New()
	user := &models.User{
		ID:    userID,
		Email: "test@example.com",
		Name:  "Test User",
		Role:  "user",
	}

	d.userRepo.On("FindByID", mock.Anything, userID).Return(user, nil)

	authSvc := newTestAuthService(d)

	profile, err := authSvc.GetProfile(context.Background(), userID.String())

	assert.NoError(t, err)
	assert.NotNil(t, profile)
	assert.Equal(t, "test@example.com", profile.Email)
	assert.Equal(t, "Test User", profile.Name)

	d.userRepo.AssertExpectations(t)
}

// TestGetProfileUserNotFound tests profile retrieval for non-existent user
func TestGetProfileUserNotFound(t *testing.T) {
	d := newTestDeps()

	userID := uuid.New()
	d.userRepo.On("FindByID", mock.Anything, userID).Return(nil, sql.ErrNoRows)

	authSvc := newTestAuthService(d)

	profile, err := authSvc.GetProfile(context.Background(), userID.String())

	assert.Error(t, err)
	assert.Equal(t, ErrUserNotFound, err)
	assert.Nil(t, profile)

	d.userRepo.AssertExpectations(t)
}

// TestGetProfileInvalidUUID tests profile retrieval with invalid UUID
func TestGetProfileInvalidUUID(t *testing.T) {
	d := newTestDeps()

	authSvc := newTestAuthService(d)

	profile, err := authSvc.GetProfile(context.Background(), "invalid-uuid")

	assert.Error(t, err)
	assert.Nil(t, profile)
}

// TestResetPasswordInvalidatesRefreshTokens tests that a successful reset
// wipes existing sessions.
func TestResetPasswordInvalidatesRefreshTokens(t *testing.T) {
	d := newTestDeps()

	userID := uuid.New()
	vt := &models.VerificationToken{
		ID:        uuid.New(),
		UserID:    userID,
		Token:     "reset-token",
		Purpose:   models.VerificationPurposePasswordReset,
		ExpiresAt: time.Now().Add(time.Hour),
	}
	user := &models.User{ID: userID, Email: "test@example.com"}

	d.verifyRepo.On("FindByToken", mock.Anything, "reset-token").Return(vt, nil)
	d.userRepo.On("FindByID", mock.Anything, userID).Return(user, nil)
	d.userRepo.On("Update", mock.Anything, mock.Anything).Return(nil)
	d.verifyRepo.On("DeleteByToken", mock.Anything, "reset-token").Return(nil)
	d.tokenRepo.On("DeleteByUserID", mock.Anything, userID).Return(nil)

	authSvc := newTestAuthService(d)

	err := authSvc.ResetPassword(context.Background(), "reset-token", "NewPassword123!")

	assert.NoError(t, err)
	d.tokenRepo.AssertExpectations(t)
}

// TestResetPasswordInvalidToken tests reset with an unknown token
func TestResetPasswordInvalidToken(t *testing.T) {
	d := newTestDeps()

	d.verifyRepo.On("FindByToken", mock.Anything, "bogus").Return(nil, sql.ErrNoRows)

	authSvc := newTestAuthService(d)

	err := authSvc.ResetPassword(context.Background(), "bogus", "NewPassword123!")

	assert.ErrorIs(t, err, ErrInvalidVerificationToken)
}

// TestTwoFAConfirmRejectsWrongCode tests that confirming 2FA with a wrong
// code doesn't enable it.
func TestTwoFAConfirmRejectsWrongCode(t *testing.T) {
	d := newTestDeps()

	userID := uuid.New()
	user := &models.User{ID: userID, Email: "test@example.com", TOTPSecret: "JBSWY3DPEHPK3PXP"}

	d.userRepo.On("FindByID", mock.Anything, userID).Return(user, nil)

	authSvc := newTestAuthService(d)

	err := authSvc.ConfirmTwoFA(context.Background(), userID.String(), "000000")

	assert.ErrorIs(t, err, ErrInvalidTwoFACode)
}
