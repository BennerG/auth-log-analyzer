package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	authlogv1 "github.com/BennerG/auth-log-analyzer/gen/authlog/v1"
	"github.com/BennerG/auth-log-analyzer/internal/api"
	"github.com/BennerG/auth-log-analyzer/internal/auth"
	"github.com/BennerG/auth-log-analyzer/internal/config"
	"github.com/BennerG/auth-log-analyzer/internal/db"
	grpcserver "github.com/BennerG/auth-log-analyzer/internal/grpc"
	"github.com/BennerG/auth-log-analyzer/internal/logger"
	"github.com/BennerG/auth-log-analyzer/internal/service"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
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

	// REST server
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

	httpSrv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  10 * time.Second,
	}

	// gRPC server
	grpcLis, err := net.Listen("tcp", ":9090")
	if err != nil {
		log.Fatal().Err(err).Msg("failed to bind gRPC port 9090")
	}

	grpcSrv := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			grpcserver.UnaryLoggingInterceptor(log.Logger),
		),
		grpc.ChainStreamInterceptor(
			grpcserver.StreamLoggingInterceptor(log.Logger),
		),
	)
	authlogv1.RegisterAuthLogServiceServer(grpcSrv, grpcserver.NewServer(pool, log.Logger))

	go func() {
		log.Info().Str("port", "9090").Msg("gRPC server starting")
		if err := grpcSrv.Serve(grpcLis); err != nil {
			log.Fatal().Err(err).Msg("gRPC server error")
		}
	}()

	// Graceful shutdown stops both servers with one signal
	go func() {
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		<-quit
		log.Info().Msg("shutdown signal received")

		grpcSrv.GracefulStop()
		log.Info().Msg("gRPC server stopped")

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()

		if err := httpSrv.Shutdown(shutdownCtx); err != nil {
			log.Fatal().Err(err).Msg("forced HTTP shutdown")
		}
	}()

	log.Info().Str("port", cfg.Port).Msg("HTTP server starting")
	if err := httpSrv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatal().Err(err).Msg("HTTP server error")
	}
	log.Info().Msg("server stopped")
}
