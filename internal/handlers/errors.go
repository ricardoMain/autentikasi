package handlers

import (
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"autentikasi/internal/models"
)

// respondError sends err mapped to status if status != 0, otherwise logs err
// server-side and responds with a generic message to avoid leaking internals.
func respondError(c *gin.Context, status int, err error) {
	if status != 0 {
		c.JSON(status, models.APIResponse{Success: false, Error: err.Error()})
		return
	}
	slog.Error("internal error", "path", c.Request.URL.Path, "error", err)
	c.JSON(http.StatusInternalServerError, models.APIResponse{Success: false, Error: "internal server error"})
}
