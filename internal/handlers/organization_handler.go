package handlers

import (
	"database/sql"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"autentikasi/internal/models"
	"autentikasi/internal/repository"
)

type OrganizationHandler struct {
	orgRepo repository.OrganizationRepositoryInterface
}

func NewOrganizationHandler(orgRepo repository.OrganizationRepositoryInterface) *OrganizationHandler {
	return &OrganizationHandler{orgRepo: orgRepo}
}

func (h *OrganizationHandler) GetMyOrganization(c *gin.Context) {
	orgIDVal, _ := c.Get("organization_id")
	orgIDStr, _ := orgIDVal.(string)

	orgID, err := uuid.Parse(orgIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Success: false, Error: "invalid organization"})
		return
	}

	org, err := h.orgRepo.FindByID(c.Request.Context(), orgID)
	if err != nil {
		status := 0
		if errors.Is(err, sql.ErrNoRows) {
			status = http.StatusNotFound
		}
		respondError(c, status, err)
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Success: true, Data: org})
}
