package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/BennerG/auth-log-analyzer/internal/api"
	"github.com/BennerG/auth-log-analyzer/internal/auth"
	"github.com/BennerG/auth-log-analyzer/internal/config"
	"github.com/BennerG/auth-log-analyzer/internal/db"
	"github.com/BennerG/auth-log-analyzer/internal/logger"
	"github.com/BennerG/auth-log-analyzer/internal/service"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

func main() {
	cfg := config.Load()

	logger.Init(cfg.Env)

	// Load RSA keys before any network connections. Fatal early if keys are
	// missing rather than discovering the problem on the first protected request.
	privateKey, err := auth.LoadPrivateKey(cfg.JWTPrivateKeyPath)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load JWT private key")
	}
	log.Info().Str("path", cfg.JWTPrivateKeyPath).Msg("JWT private key loaded")

	publicKey, err := auth.LoadPublicKey(cfg.JWTPublicKeyPath)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load JWT public key")
	}
	log.Info().Str("path", cfg.JWTPublicKeyPath).Msg("JWT public key loaded")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := db.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to connect to database")
	}
	defer pool.Close()
	log.Info().Msg("database connection pool established")

	// Redis is used exclusively for per-IP rate limiting.
	opt, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		log.Fatal().Err(err).Msg("invalid redis URL")
	}
	redisClient := redis.NewClient(opt)

	redisCtx, redisCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer redisCancel()

	if err := redisClient.Ping(redisCtx).Err(); err != nil {
		log.Fatal().Err(err).Msg("failed to connect to redis")
	}
	defer redisClient.Close()
	log.Info().Msg("redis connection established")

	svc := service.NewEventService(pool)

	router := api.NewRouter(
		svc,
		privateKey,
		publicKey,
		redisClient,
		cfg.RateLimitConfig(),
		cfg.AdminUsername,
		cfg.AdminPassword,
		cfg.JWTExpiry,
	)

	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  10 * time.Second,
	}

	// graceful shutdown
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
