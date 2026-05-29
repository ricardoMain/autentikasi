package main

import (
	"log"

	"github.com/gin-gonic/gin"
	"autentikasi/internal/config"
	"autentikasi/internal/database"
	"autentikasi/internal/handlers"
	"autentikasi/internal/repository"
	"autentikasi/internal/routes"
	"autentikasi/internal/services"
)

func main() {
	cfg := config.Load()

	prisma := database.Connect(cfg.DatabaseURL)
	defer prisma.Close()

	userRepo := repository.NewUserRepository(prisma)
	tokenRepo := repository.NewTokenRepository(prisma)
	tokenSvc := services.NewTokenService(cfg)
	authSvc := services.NewAuthService(userRepo, tokenRepo, tokenSvc, cfg)
	oauthSvc := services.NewOAuthService(cfg, userRepo, authSvc)

	authHandler := handlers.NewAuthHandler(authSvc)
	oauthHandler := handlers.NewOAuthHandler(oauthSvc)

	r := gin.Default()

	routes.Setup(r, authHandler, oauthHandler, tokenSvc)

	log.Printf("server starting on port %s", cfg.ServerPort)
	if err := r.Run(":" + cfg.ServerPort); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
