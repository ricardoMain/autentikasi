package handlers

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"autentikasi/internal/models"
	"autentikasi/internal/services"
)

type TwoFAHandler struct {
	authSvc *services.AuthService
}

func NewTwoFAHandler(authSvc *services.AuthService) *TwoFAHandler {
	return &TwoFAHandler{authSvc: authSvc}
}

func (h *TwoFAHandler) Setup(c *gin.Context) {
	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	resp, err := h.authSvc.SetupTwoFA(c.Request.Context(), userIDStr)
	if err != nil {
		respondError(c, 0, err)
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Success: true, Data: resp})
}

func (h *TwoFAHandler) Confirm(c *gin.Context) {
	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	var req models.TwoFACodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Success: false, Error: err.Error()})
		return
	}

	if err := h.authSvc.ConfirmTwoFA(c.Request.Context(), userIDStr, req.Code); err != nil {
		status := 0
		if errors.Is(err, services.ErrInvalidTwoFACode) {
			status = http.StatusUnauthorized
		}
		respondError(c, status, err)
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Success: true, Message: "two-factor authentication enabled"})
}

func (h *TwoFAHandler) Disable(c *gin.Context) {
	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	var req models.TwoFACodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Success: false, Error: err.Error()})
		return
	}

	if err := h.authSvc.DisableTwoFA(c.Request.Context(), userIDStr, req.Code); err != nil {
		status := 0
		if errors.Is(err, services.ErrInvalidTwoFACode) {
			status = http.StatusUnauthorized
		}
		respondError(c, status, err)
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Success: true, Message: "two-factor authentication disabled"})
}

func (h *TwoFAHandler) Login(c *gin.Context) {
	var req models.TwoFALoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Success: false, Error: err.Error()})
		return
	}

	resp, err := h.authSvc.LoginWithTwoFA(c.Request.Context(), req.TempToken, req.Code)
	if err != nil {
		status := 0
		if errors.Is(err, services.ErrInvalidToken) || errors.Is(err, services.ErrInvalidTwoFACode) {
			status = http.StatusUnauthorized
		}
		respondError(c, status, err)
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Success: true, Message: "login successful", Data: resp})
}
