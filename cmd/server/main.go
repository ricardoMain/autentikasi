package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

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
	oauthHandler := handlers.NewOAuthHandler(oauthSvc, cfg.SecureCookie)

	r := gin.Default()

	routes.Setup(r, authHandler, oauthHandler, tokenSvc)

	srv := &http.Server{
		Addr:    ":" + cfg.ServerPort,
		Handler: r,
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Printf("server starting on port %s", cfg.ServerPort)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	<-quit
	log.Println("shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("server forced to shutdown: %v", err)
	}

	log.Println("server exited")
}
