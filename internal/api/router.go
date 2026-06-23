package api

import (
	"crypto/rsa"
	"time"

	"github.com/BennerG/auth-log-analyzer/internal/api/handlers"
	"github.com/BennerG/auth-log-analyzer/internal/auth"
	"github.com/BennerG/auth-log-analyzer/internal/metrics"
	"github.com/BennerG/auth-log-analyzer/internal/ratelimit"
	"github.com/BennerG/auth-log-analyzer/internal/service"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
)

// RateLimitConfig holds per-endpoint rate limits populated from env vars.
type RateLimitConfig struct {
	IngestLimit   int // POST /events writes to Postgres
	EventsLimit   int // GET /events reads for dashboard polling
	AnalysisLimit int // GET /analysis/* aggregation queries
}

func NewRouter(
	svc *service.EventService,
	privateKey *rsa.PrivateKey,
	publicKey *rsa.PublicKey,
	rdb *redis.Client,
	cfg RateLimitConfig,
	adminUsername string,
	adminPassword string,
	jwtExpiry time.Duration,
) *chi.Mux {
	r := chi.NewRouter()

	// Global middleware
	r.Use(metrics.InstrumentHandler)
	r.Use(middleware.RequestID)
	// TODO: middleware.RealIP trusts XFF header blindly, enabling IP spoofing.
	// Replace with right-to-left XFF traversal against a known proxy allowlist.
	// See: github.com/go-chi/chi/security/advisories/GHSA-3fxj-6jh8-hvhx
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Handlers
	healthHandler := handlers.NewHealthHandler()
	eventHandler := handlers.NewEventHandler(svc)
	analysisHandler := handlers.NewAnalysisHandler(svc)
	authHandler := handlers.NewAuthHandler(privateKey, adminUsername, adminPassword, jwtExpiry)

	// Public routes
	r.Get("/health", healthHandler.Health)
	r.Handle("/metrics", promhttp.Handler())
	r.Post("/auth/login", authHandler.Login)

	// Protected routes
	r.Group(func(r chi.Router) {
		r.Use(auth.JWTMiddleware(publicKey))

		// 120 req/min for event listing
		r.With(ratelimit.New(rdb, cfg.EventsLimit, time.Minute)).Get("/events", eventHandler.ListEvents)

		// 30 req/min for writes and aggregation queries
		r.With(ratelimit.New(rdb, cfg.IngestLimit, time.Minute)).Post("/events", eventHandler.CreateEvent)
		r.With(ratelimit.New(rdb, cfg.AnalysisLimit, time.Minute)).Get("/analysis/suspicious-ips", analysisHandler.SuspiciousIPs)
		r.With(ratelimit.New(rdb, cfg.AnalysisLimit, time.Minute)).Get("/analysis/user-activity", analysisHandler.UserActivity)
	})

	return r
}
