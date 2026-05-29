package routes

import (
	"github.com/gin-gonic/gin"
	"autentikasi/internal/handlers"
	"autentikasi/internal/middleware"
	"autentikasi/internal/services"
)

func Setup(
	r *gin.Engine,
	authHandler *handlers.AuthHandler,
	oauthHandler *handlers.OAuthHandler,
	tokenSvc *services.TokenService,
) {
	api := r.Group("/api")
	{
		auth := api.Group("/auth")
		{
			auth.POST("/register", authHandler.Register)
			auth.POST("/login", authHandler.Login)
			auth.POST("/refresh", authHandler.Refresh)
			auth.POST("/logout", authHandler.Logout)

			auth.GET("/google/login", oauthHandler.GoogleLogin)
			auth.GET("/google/callback", oauthHandler.GoogleCallback)
			auth.GET("/github/login", oauthHandler.GitHubLogin)
			auth.GET("/github/callback", oauthHandler.GitHubCallback)

			auth.GET("/me", middleware.AuthMiddleware(tokenSvc), authHandler.Me)
		}

		admin := api.Group("/admin")
		admin.Use(middleware.AuthMiddleware(tokenSvc))
		admin.Use(middleware.RequireRole("admin", "superadmin"))
		{
			admin.GET("/dashboard", func(c *gin.Context) {
				c.JSON(200, gin.H{"message": "admin dashboard"})
			})
		}
	}
}
