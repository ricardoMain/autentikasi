package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"autentikasi/internal/config"
	"autentikasi/internal/services"
)

func newTestTokenService() *services.TokenService {
	return services.NewTokenService(&config.Config{
		JWTSecret: "test-secret",
		JWTExpiry: time.Minute,
	})
}

func runAuthMiddleware(t *testing.T, header string) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(AuthMiddleware(newTestTokenService()))
	r.GET("/protected", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	if header != "" {
		req.Header.Set("Authorization", header)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestAuthMiddleware_MissingHeader(t *testing.T) {
	w := runAuthMiddleware(t, "")
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthMiddleware_InvalidToken(t *testing.T) {
	w := runAuthMiddleware(t, "Bearer not-a-real-token")
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthMiddleware_ValidToken(t *testing.T) {
	tokenSvc := newTestTokenService()
	token, err := tokenSvc.GenerateAccessToken(uuid.New(), "user@example.com", "user", uuid.New())
	assert.NoError(t, err)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(AuthMiddleware(tokenSvc))
	r.GET("/protected", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}
