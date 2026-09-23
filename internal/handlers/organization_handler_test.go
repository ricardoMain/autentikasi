package handlers

import (
	"database/sql"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"autentikasi/internal/models"
)

func withOrgID(orgID string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("organization_id", orgID)
		c.Next()
	}
}

func TestGetMyOrganization_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	orgID := uuid.New()
	orgRepo := new(mockOrgRepo)
	orgRepo.On("FindByID", mock.Anything, orgID).Return(&models.Organization{ID: orgID, Name: "Acme"}, nil)

	h := NewOrganizationHandler(orgRepo)
	r := gin.New()
	r.Use(withOrgID(orgID.String()))
	r.GET("/organizations/me", h.GetMyOrganization)

	w := doRequest(r, http.MethodGet, "/organizations/me", nil)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetMyOrganization_NotFound(t *testing.T) {
	gin.SetMode(gin.TestMode)
	orgID := uuid.New()
	orgRepo := new(mockOrgRepo)
	orgRepo.On("FindByID", mock.Anything, orgID).Return(nil, sql.ErrNoRows)

	h := NewOrganizationHandler(orgRepo)
	r := gin.New()
	r.Use(withOrgID(orgID.String()))
	r.GET("/organizations/me", h.GetMyOrganization)

	w := doRequest(r, http.MethodGet, "/organizations/me", nil)
	assert.Equal(t, http.StatusNotFound, w.Code)
}
