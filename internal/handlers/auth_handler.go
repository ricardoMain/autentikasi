package handlers

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"autentikasi/internal/models"
	"autentikasi/internal/services"
)

type AuthHandler struct {
	authSvc *services.AuthService
}

func NewAuthHandler(authSvc *services.AuthService) *AuthHandler {
	return &AuthHandler{authSvc: authSvc}
}

func (h *AuthHandler) Register(c *gin.Context) {
	var req models.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	resp, err := h.authSvc.Register(c.Request.Context(), req)
	if err != nil {
		status := 0
		if errors.Is(err, services.ErrEmailAlreadyExists) {
			status = http.StatusConflict
		}
		respondError(c, status, err)
		return
	}

	c.JSON(http.StatusCreated, models.APIResponse{
		Success: true,
		Message: "registration successful",
		Data:    resp,
	})
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req models.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	resp, err := h.authSvc.Login(c.Request.Context(), req)
	if err != nil {
		status := 0
		if errors.Is(err, services.ErrInvalidCredentials) {
			status = http.StatusUnauthorized
		}
		respondError(c, status, err)
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Message: "login successful",
		Data:    resp,
	})
}

func (h *AuthHandler) Refresh(c *gin.Context) {
	var req models.RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	resp, err := h.authSvc.Refresh(c.Request.Context(), req.RefreshToken)
	if err != nil {
		status := 0
		if errors.Is(err, services.ErrInvalidToken) {
			status = http.StatusUnauthorized
		}
		respondError(c, status, err)
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Message: "token refreshed",
		Data:    resp,
	})
}

func (h *AuthHandler) Logout(c *gin.Context) {
	var req models.RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	if err := h.authSvc.Logout(c.Request.Context(), req.RefreshToken); err != nil {
		respondError(c, 0, err)
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Message: "logged out successfully",
	})
}

func (h *AuthHandler) VerifyEmail(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Success: false, Error: "token is required"})
		return
	}

	if err := h.authSvc.VerifyEmail(c.Request.Context(), token); err != nil {
		status := 0
		if errors.Is(err, services.ErrInvalidVerificationToken) || errors.Is(err, services.ErrUserNotFound) {
			status = http.StatusBadRequest
		}
		respondError(c, status, err)
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Success: true, Message: "email verified"})
}

func (h *AuthHandler) ForgotPassword(c *gin.Context) {
	var req models.ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Success: false, Error: err.Error()})
		return
	}

	if err := h.authSvc.ForgotPassword(c.Request.Context(), req.Email); err != nil {
		respondError(c, 0, err)
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Message: "if that email is registered, a reset link has been sent",
	})
}

func (h *AuthHandler) ResetPassword(c *gin.Context) {
	var req models.ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Success: false, Error: err.Error()})
		return
	}

	if err := h.authSvc.ResetPassword(c.Request.Context(), req.Token, req.NewPassword); err != nil {
		status := 0
		if errors.Is(err, services.ErrInvalidVerificationToken) || errors.Is(err, services.ErrUserNotFound) {
			status = http.StatusBadRequest
		}
		respondError(c, status, err)
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Success: true, Message: "password reset successful"})
}

func (h *AuthHandler) Me(c *gin.Context) {
	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	user, err := h.authSvc.GetProfile(c.Request.Context(), userIDStr)
	if err != nil {
		status := 0
		if errors.Is(err, services.ErrUserNotFound) {
			status = http.StatusNotFound
		}
		respondError(c, status, err)
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Data:    user,
	})
}
