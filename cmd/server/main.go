package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/BennerG/auth-log-analyzer/internal/api"
	"github.com/BennerG/auth-log-analyzer/internal/config"
	"github.com/BennerG/auth-log-analyzer/internal/db"
	"github.com/BennerG/auth-log-analyzer/internal/logger"
	"github.com/BennerG/auth-log-analyzer/internal/service"
	"github.com/rs/zerolog/log"
)

func main() {
	cfg := config.Load()

	logger.Init(cfg.Env)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := db.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to connect to database")
	}
	defer pool.Close()
	log.Info().Msg("database connection pool established")

	svc := service.NewEventService(pool)
	router := api.NewRouter(svc, cfg.APIKey)

	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  10 * time.Second,
	}

	go func() {
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		<-quit
		log.Info().Msg("shutdown signal received")

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()

		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Fatal().Err(err).Msg("forced shutdown")
		}
	}()

	log.Info().Str("port", cfg.Port).Msg("server starting")
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatal().Err(err).Msg("server error")
	}
	log.Info().Msg("server stopped")
}
