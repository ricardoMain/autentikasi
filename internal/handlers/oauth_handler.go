package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"autentikasi/internal/models"
	"autentikasi/internal/services"
)

type OAuthHandler struct {
	oauthSvc *services.OAuthService
}

func NewOAuthHandler(oauthSvc *services.OAuthService) *OAuthHandler {
	return &OAuthHandler{oauthSvc: oauthSvc}
}

func (h *OAuthHandler) GoogleLogin(c *gin.Context) {
	state := services.GenerateState()
	c.SetCookie("oauth_state", state, 600, "/", "", false, true)
	url := h.oauthSvc.GetGoogleLoginURL(state)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

func (h *OAuthHandler) GoogleCallback(c *gin.Context) {
	code := c.Query("code")
	state := c.Query("state")

	cookieState, _ := c.Cookie("oauth_state")
	if state == "" || state != cookieState {
		c.JSON(http.StatusUnauthorized, models.APIResponse{
			Success: false,
			Error:   "invalid state parameter",
		})
		return
	}

	c.SetCookie("oauth_state", "", -1, "/", "", false, true)

	resp, err := h.oauthSvc.HandleGoogleCallback(c.Request.Context(), code)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Message: "google login successful",
		Data:    resp,
	})
}

func (h *OAuthHandler) GitHubLogin(c *gin.Context) {
	state := services.GenerateState()
	c.SetCookie("oauth_state", state, 600, "/", "", false, true)
	url := h.oauthSvc.GetGitHubLoginURL(state)
	c.Redirect(http.StatusTemporaryRedirect, url)
}

func (h *OAuthHandler) GitHubCallback(c *gin.Context) {
	code := c.Query("code")
	state := c.Query("state")

	cookieState, _ := c.Cookie("oauth_state")
	if state == "" || state != cookieState {
		c.JSON(http.StatusUnauthorized, models.APIResponse{
			Success: false,
			Error:   "invalid state parameter",
		})
		return
	}

	c.SetCookie("oauth_state", "", -1, "/", "", false, true)

	resp, err := h.oauthSvc.HandleGitHubCallback(c.Request.Context(), code)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Error:   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Message: "github login successful",
		Data:    resp,
	})
}
