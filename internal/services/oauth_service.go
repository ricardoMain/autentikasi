package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
	"autentikasi/internal/config"
	"autentikasi/internal/models"
	"autentikasi/internal/repository"
)

type OAuthService struct {
	googleOAuthConfig *oauth2.Config
	githubOAuthConfig *oauth2.Config
	userRepo          *repository.UserRepository
	authSvc           *AuthService
}

func NewOAuthService(cfg *config.Config, userRepo *repository.UserRepository, authSvc *AuthService) *OAuthService {
	return &OAuthService{
		googleOAuthConfig: &oauth2.Config{
			ClientID:     cfg.GoogleClientID,
			ClientSecret: cfg.GoogleClientSecret,
			RedirectURL:  cfg.GoogleRedirectURL,
			Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"},
			Endpoint:     google.Endpoint,
		},
		githubOAuthConfig: &oauth2.Config{
			ClientID:     cfg.GitHubClientID,
			ClientSecret: cfg.GitHubClientSecret,
			RedirectURL:  cfg.GitHubRedirectURL,
			Scopes:       []string{"user:email", "read:user"},
			Endpoint:     github.Endpoint,
		},
		userRepo: userRepo,
		authSvc:  authSvc,
	}
}

type GoogleUserInfo struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

type GitHubUserInfo struct {
	ID        int    `json:"id"`
	Login     string `json:"login"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	AvatarURL string `json:"avatar_url"`
}

type GitHubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

func (s *OAuthService) GetGoogleLoginURL(state string) string {
	return s.googleOAuthConfig.AuthCodeURL(state, oauth2.AccessTypeOffline)
}

func (s *OAuthService) GetGitHubLoginURL(state string) string {
	return s.githubOAuthConfig.AuthCodeURL(state, oauth2.AccessTypeOffline)
}

func (s *OAuthService) HandleGoogleCallback(ctx context.Context, code string) (*models.AuthResponse, error) {
	token, err := s.googleOAuthConfig.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}

	client := s.googleOAuthConfig.Client(ctx, token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var googleUser GoogleUserInfo
	if err := json.Unmarshal(body, &googleUser); err != nil {
		return nil, fmt.Errorf("failed to parse user info: %w", err)
	}

	return s.findOrCreateUser(ctx, "google", fmt.Sprintf("%v", googleUser.ID), googleUser.Email, googleUser.Name, googleUser.Picture)
}

func (s *OAuthService) HandleGitHubCallback(ctx context.Context, code string) (*models.AuthResponse, error) {
	token, err := s.githubOAuthConfig.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}

	client := s.githubOAuthConfig.Client(ctx, token)
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var githubUser GitHubUserInfo
	if err := json.Unmarshal(body, &githubUser); err != nil {
		return nil, fmt.Errorf("failed to parse user info: %w", err)
	}

	if githubUser.Email == "" {
		email, err := s.fetchGitHubPrimaryEmail(client)
		if err != nil {
			return nil, err
		}
		githubUser.Email = email
	}

	userID := fmt.Sprintf("%d", githubUser.ID)
	name := githubUser.Name
	if name == "" {
		name = githubUser.Login
	}

	return s.findOrCreateUser(ctx, "github", userID, githubUser.Email, name, githubUser.AvatarURL)
}

func (s *OAuthService) fetchGitHubPrimaryEmail(client *http.Client) (string, error) {
	resp, err := client.Get("https://api.github.com/user/emails")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var emails []GitHubEmail
	if err := json.Unmarshal(body, &emails); err != nil {
		return "", err
	}

	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, nil
		}
	}

	if len(emails) > 0 {
		return emails[0].Email, nil
	}

	return "", errors.New("no email found")
}

func (s *OAuthService) findOrCreateUser(ctx context.Context, provider, providerID, email, name, avatarURL string) (*models.AuthResponse, error) {
	user, err := s.userRepo.FindByProvider(ctx, provider, providerID)
	if err == nil {
		return s.authSvc.generateTokens(ctx, user)
	}

	user = &models.User{
		Email:      email,
		Name:       name,
		AvatarURL:  avatarURL,
		Role:       "user",
		Provider:   provider,
		ProviderID: providerID,
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, err
	}

	return s.authSvc.generateTokens(ctx, user)
}

func GenerateState() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
