package routes

import (
	"time"

	"github.com/gin-gonic/gin"
	"autentikasi/internal/handlers"
	"autentikasi/internal/middleware"
	"autentikasi/internal/services"
)

func Setup(
	r *gin.Engine,
	authHandler *handlers.AuthHandler,
	oauthHandler *handlers.OAuthHandler,
	twoFAHandler *handlers.TwoFAHandler,
	orgHandler *handlers.OrganizationHandler,
	tokenSvc *services.TokenService,
	frontendURL string,
) {
	r.Use(middleware.CORS(frontendURL))

	rl := middleware.RateLimit(10, time.Minute)
	authed := middleware.AuthMiddleware(tokenSvc)

	api := r.Group("/api")
	{
		auth := api.Group("/auth")
		{
			auth.POST("/register", rl, authHandler.Register)
			auth.POST("/login", rl, authHandler.Login)
			auth.POST("/refresh", rl, authHandler.Refresh)
			auth.POST("/logout", rl, authHandler.Logout)
			auth.GET("/verify-email", rl, authHandler.VerifyEmail)
			auth.POST("/forgot-password", rl, authHandler.ForgotPassword)
			auth.POST("/reset-password", rl, authHandler.ResetPassword)

			auth.GET("/google/login", oauthHandler.GoogleLogin)
			auth.GET("/google/callback", oauthHandler.GoogleCallback)
			auth.GET("/github/login", oauthHandler.GitHubLogin)
			auth.GET("/github/callback", oauthHandler.GitHubCallback)

			auth.GET("/me", authed, authHandler.Me)

			twofa := auth.Group("/2fa")
			{
				twofa.POST("/login", rl, twoFAHandler.Login)
				twofa.POST("/setup", authed, twoFAHandler.Setup)
				twofa.POST("/confirm", authed, twoFAHandler.Confirm)
				twofa.POST("/disable", authed, twoFAHandler.Disable)
			}
		}

		orgs := api.Group("/organizations")
		orgs.Use(authed)
		{
			orgs.GET("/me", orgHandler.GetMyOrganization)
		}

		admin := api.Group("/admin")
		admin.Use(authed)
		admin.Use(middleware.RequireRole("admin", "superadmin"))
		{
			admin.GET("/dashboard", func(c *gin.Context) {
				c.JSON(200, gin.H{"message": "admin dashboard"})
			})
		}
	}
}
