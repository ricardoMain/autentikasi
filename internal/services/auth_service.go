package services

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"autentikasi/internal/config"
	"autentikasi/internal/models"
	"autentikasi/internal/repository"
)

var (
	ErrEmailAlreadyExists = errors.New("email already registered")
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrInvalidToken       = errors.New("invalid or expired refresh token")
	ErrUserNotFound       = errors.New("user not found")
)

type AuthService struct {
	userRepo  repository.UserRepositoryInterface
	tokenRepo repository.TokenRepositoryInterface
	tokenSvc  *TokenService
	cfg       *config.Config
}

func NewAuthService(
	userRepo repository.UserRepositoryInterface,
	tokenRepo repository.TokenRepositoryInterface,
	tokenSvc *TokenService,
	cfg *config.Config,
) *AuthService {
	return &AuthService{
		userRepo:  userRepo,
		tokenRepo: tokenRepo,
		tokenSvc:  tokenSvc,
		cfg:       cfg,
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

	user := &models.User{
		Email:    req.Email,
		Password: string(hashedPassword),
		Name:     req.Name,
		Role:     "user",
		Provider: "local",
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, err
	}

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

func parseUUID(s string) (uuid.UUID, error) {
	return uuid.Parse(s)
}

func (s *AuthService) generateTokens(ctx context.Context, user *models.User) (*models.AuthResponse, error) {
	accessToken, err := s.tokenSvc.GenerateAccessToken(user.ID, user.Email, user.Role)
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
		User:         *user,
	}, nil
}
