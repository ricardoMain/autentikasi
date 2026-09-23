package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func runRBACMiddleware(role string, setRole bool) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		if setRole {
			c.Set("role", role)
		}
		c.Next()
	})
	r.Use(RequireRole("admin", "superadmin"))
	r.GET("/admin", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/admin", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestRequireRole_Allowed(t *testing.T) {
	w := runRBACMiddleware("admin", true)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequireRole_Denied(t *testing.T) {
	w := runRBACMiddleware("user", true)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestRequireRole_NoRoleSet(t *testing.T) {
	w := runRBACMiddleware("", false)
	assert.Equal(t, http.StatusForbidden, w.Code)
}
