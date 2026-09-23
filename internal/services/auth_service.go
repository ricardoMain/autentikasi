package services

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/crypto/bcrypt"
	"autentikasi/internal/config"
	"autentikasi/internal/models"
	"autentikasi/internal/repository"
)

// uniqueViolationCode is Postgres' error code for a unique constraint conflict.
const uniqueViolationCode = "23505"

var (
	ErrEmailAlreadyExists       = errors.New("email already registered")
	ErrInvalidCredentials       = errors.New("invalid email or password")
	ErrInvalidToken             = errors.New("invalid or expired refresh token")
	ErrUserNotFound             = errors.New("user not found")
	ErrInvalidVerificationToken = errors.New("invalid or expired token")
	ErrInvalidTwoFACode         = errors.New("invalid two-factor code")
)

type AuthService struct {
	userRepo   repository.UserRepositoryInterface
	tokenRepo  repository.TokenRepositoryInterface
	orgRepo    repository.OrganizationRepositoryInterface
	verifyRepo repository.VerificationTokenRepositoryInterface
	tokenSvc   *TokenService
	emailSvc   *EmailService
	totpSvc    *TOTPService
	cfg        *config.Config
}

func NewAuthService(
	userRepo repository.UserRepositoryInterface,
	tokenRepo repository.TokenRepositoryInterface,
	orgRepo repository.OrganizationRepositoryInterface,
	verifyRepo repository.VerificationTokenRepositoryInterface,
	tokenSvc *TokenService,
	emailSvc *EmailService,
	totpSvc *TOTPService,
	cfg *config.Config,
) *AuthService {
	return &AuthService{
		userRepo:   userRepo,
		tokenRepo:  tokenRepo,
		orgRepo:    orgRepo,
		verifyRepo: verifyRepo,
		tokenSvc:   tokenSvc,
		emailSvc:   emailSvc,
		totpSvc:    totpSvc,
		cfg:        cfg,
	}
}

func (s *AuthService) Register(ctx context.Context, req models.RegisterRequest) (*models.AuthResponse, error) {
	existing, _ := s.userRepo.FindByEmail(ctx, req.Email)
	if existing != nil {
		return nil, ErrEmailAlreadyExists
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	org, err := s.createOrganization(ctx, req.OrganizationName)
	if err != nil {
		return nil, err
	}

	user := &models.User{
		Email:          req.Email,
		Password:       string(hashedPassword),
		Name:           req.Name,
		Role:           "user",
		Provider:       "local",
		OrganizationID: org.ID,
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == uniqueViolationCode {
			return nil, ErrEmailAlreadyExists
		}
		return nil, err
	}

	s.sendVerificationEmail(ctx, user)

	return s.generateTokens(ctx, user)
}

func (s *AuthService) Login(ctx context.Context, req models.LoginRequest) (*models.AuthResponse, error) {
	user, err := s.userRepo.FindByEmail(ctx, req.Email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	if user.TOTPEnabled {
		tempToken, err := s.tokenSvc.GenerateTwoFAPendingToken(user.ID)
		if err != nil {
			return nil, err
		}
		return &models.AuthResponse{Requires2FA: true, TempToken: tempToken}, nil
	}

	return s.generateTokens(ctx, user)
}

// LoginWithTwoFA completes a login that was paused by Login for TOTP
// confirmation.
func (s *AuthService) LoginWithTwoFA(ctx context.Context, tempToken, code string) (*models.AuthResponse, error) {
	userID, err := s.tokenSvc.ValidateTwoFAPendingToken(tempToken)
	if err != nil {
		return nil, ErrInvalidToken
	}

	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return nil, ErrUserNotFound
	}

	if !user.TOTPEnabled || !s.totpSvc.ValidateCode(user.TOTPSecret, code) {
		return nil, ErrInvalidTwoFACode
	}

	return s.generateTokens(ctx, user)
}

func (s *AuthService) Refresh(ctx context.Context, refreshToken string) (*models.AuthResponse, error) {
	storedToken, err := s.tokenRepo.FindByToken(ctx, refreshToken)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrInvalidToken
		}
		return nil, err
	}

	if time.Now().After(storedToken.ExpiresAt) {
		s.tokenRepo.DeleteByToken(ctx, refreshToken)
		return nil, ErrInvalidToken
	}

	user, err := s.userRepo.FindByID(ctx, storedToken.UserID)
	if err != nil {
		return nil, ErrUserNotFound
	}

	if err := s.tokenRepo.DeleteByToken(ctx, refreshToken); err != nil {
		return nil, err
	}

	return s.generateTokens(ctx, user)
}

func (s *AuthService) Logout(ctx context.Context, refreshToken string) error {
	return s.tokenRepo.DeleteByToken(ctx, refreshToken)
}

func (s *AuthService) GetProfile(ctx context.Context, userID string) (*models.User, error) {
	uid, err := parseUUID(userID)
	if err != nil {
		return nil, err
	}

	user, err := s.userRepo.FindByID(ctx, uid)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	return user, nil
}

// VerifyEmail marks the user owning the token as verified.
func (s *AuthService) VerifyEmail(ctx context.Context, token string) error {
	vt, err := s.verifyRepo.FindByToken(ctx, token)
	if err != nil {
		return ErrInvalidVerificationToken
	}
	if vt.Purpose != models.VerificationPurposeEmailVerify || time.Now().After(vt.ExpiresAt) {
		s.verifyRepo.DeleteByToken(ctx, token)
		return ErrInvalidVerificationToken
	}

	user, err := s.userRepo.FindByID(ctx, vt.UserID)
	if err != nil {
		return ErrUserNotFound
	}

	user.EmailVerified = true
	if err := s.userRepo.Update(ctx, user); err != nil {
		return err
	}

	return s.verifyRepo.DeleteByToken(ctx, token)
}

// ForgotPassword always succeeds from the caller's perspective so it never
// reveals whether an email is registered.
func (s *AuthService) ForgotPassword(ctx context.Context, email string) error {
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		return nil
	}

	token, err := s.tokenSvc.GenerateRandomToken()
	if err != nil {
		return err
	}
	if _, err := s.verifyRepo.Create(ctx, user.ID, token, models.VerificationPurposePasswordReset, time.Now().Add(time.Hour)); err != nil {
		return err
	}

	link := fmt.Sprintf("%s/reset-password?token=%s", s.cfg.FrontendURL, token)
	if err := s.emailSvc.Send(user.Email, "Reset your password", "Reset your password: "+link); err != nil {
		slog.Error("failed to send password reset email", "error", err)
	}
	return nil
}

func (s *AuthService) ResetPassword(ctx context.Context, token, newPassword string) error {
	vt, err := s.verifyRepo.FindByToken(ctx, token)
	if err != nil {
		return ErrInvalidVerificationToken
	}
	if vt.Purpose != models.VerificationPurposePasswordReset || time.Now().After(vt.ExpiresAt) {
		s.verifyRepo.DeleteByToken(ctx, token)
		return ErrInvalidVerificationToken
	}

	user, err := s.userRepo.FindByID(ctx, vt.UserID)
	if err != nil {
		return ErrUserNotFound
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	user.Password = string(hashed)
	if err := s.userRepo.Update(ctx, user); err != nil {
		return err
	}

	s.verifyRepo.DeleteByToken(ctx, token)
	// A password reset invalidates every existing session.
	return s.tokenRepo.DeleteByUserID(ctx, user.ID)
}

// SetupTwoFA generates a new TOTP secret for the user but leaves 2FA
// disabled until ConfirmTwoFA verifies the user can produce a valid code.
func (s *AuthService) SetupTwoFA(ctx context.Context, userID string) (*models.TwoFASetupResponse, error) {
	user, err := s.GetProfile(ctx, userID)
	if err != nil {
		return nil, err
	}

	secret, uri, err := s.totpSvc.GenerateSecret(user.Email)
	if err != nil {
		return nil, err
	}

	user.TOTPSecret = secret
	if err := s.userRepo.Update(ctx, user); err != nil {
		return nil, err
	}

	return &models.TwoFASetupResponse{Secret: secret, ProvisioningURI: uri}, nil
}

func (s *AuthService) ConfirmTwoFA(ctx context.Context, userID, code string) error {
	user, err := s.GetProfile(ctx, userID)
	if err != nil {
		return err
	}
	if user.TOTPSecret == "" || !s.totpSvc.ValidateCode(user.TOTPSecret, code) {
		return ErrInvalidTwoFACode
	}

	user.TOTPEnabled = true
	return s.userRepo.Update(ctx, user)
}

func (s *AuthService) DisableTwoFA(ctx context.Context, userID, code string) error {
	user, err := s.GetProfile(ctx, userID)
	if err != nil {
		return err
	}
	if !user.TOTPEnabled || !s.totpSvc.ValidateCode(user.TOTPSecret, code) {
		return ErrInvalidTwoFACode
	}

	user.TOTPEnabled = false
	user.TOTPSecret = ""
	return s.userRepo.Update(ctx, user)
}

func parseUUID(s string) (uuid.UUID, error) {
	return uuid.Parse(s)
}

func (s *AuthService) generateTokens(ctx context.Context, user *models.User) (*models.AuthResponse, error) {
	accessToken, err := s.tokenSvc.GenerateAccessToken(user.ID, user.Email, user.Role, user.OrganizationID)
	if err != nil {
		return nil, err
	}

	refreshTokenStr, err := s.tokenSvc.GenerateRefreshToken()
	if err != nil {
		return nil, err
	}

	_, err = s.tokenRepo.Create(ctx, user.ID, refreshTokenStr, time.Now().Add(s.cfg.RefreshExpiry))
	if err != nil {
		return nil, err
	}

	return &models.AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshTokenStr,
		User:         user,
	}, nil
}

// sendVerificationEmail is best-effort: a delivery failure must not block
// registration, so errors are logged, not returned.
func (s *AuthService) sendVerificationEmail(ctx context.Context, user *models.User) {
	token, err := s.tokenSvc.GenerateRandomToken()
	if err != nil {
		slog.Error("failed to generate verification token", "error", err)
		return
	}
	if _, err := s.verifyRepo.Create(ctx, user.ID, token, models.VerificationPurposeEmailVerify, time.Now().Add(24*time.Hour)); err != nil {
		slog.Error("failed to store verification token", "error", err)
		return
	}

	link := fmt.Sprintf("%s/verify-email?token=%s", s.cfg.FrontendURL, token)
	if err := s.emailSvc.Send(user.Email, "Verify your email", "Verify your email: "+link); err != nil {
		slog.Error("failed to send verification email", "error", err)
	}
}

func (s *AuthService) createOrganization(ctx context.Context, name string) (*models.Organization, error) {
	suffix, err := s.tokenSvc.GenerateRandomToken()
	if err != nil {
		return nil, err
	}
	org := &models.Organization{
		Name: name,
		Slug: slugify(name) + "-" + suffix[:6],
	}
	if err := s.orgRepo.Create(ctx, org); err != nil {
		return nil, err
	}
	return org, nil
}

// slugify lowercases name and keeps only [a-z0-9-], collapsing everything
// else into single dashes. Uniqueness is handled by the random suffix the
// caller appends, not by this function.
func slugify(name string) string {
	var b strings.Builder
	prevDash := false
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9':
			b.WriteRune(r)
			prevDash = false
		default:
			if !prevDash && b.Len() > 0 {
				b.WriteRune('-')
				prevDash = true
			}
		}
	}
	s := strings.TrimRight(b.String(), "-")
	if s == "" {
		s = "org"
	}
	return s
}
