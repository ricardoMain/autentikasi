package main

import (
	"context"
	"log/slog"
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

	db := database.Connect(cfg.DatabaseURL)
	defer db.Client.Close()

	userRepo := repository.NewUserRepository(db.Client)
	tokenRepo := repository.NewTokenRepository(db.Client)
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go database.CleanupExpiredTokens(ctx, db.SQL)

	go func() {
		slog.Info("server starting", "port", cfg.ServerPort)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	sig := <-quit
	slog.Info("shutting down server...", "signal", sig)

	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("server forced to shutdown", "error", err)
		os.Exit(1)
	}

	slog.Info("server exited")
}
