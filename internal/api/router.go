package api

import (
	"github.com/BennerG/auth-log-analyzer/internal/api/handlers"
	"github.com/BennerG/auth-log-analyzer/internal/auth"
	"github.com/BennerG/auth-log-analyzer/internal/metrics"
	"github.com/BennerG/auth-log-analyzer/internal/service"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func NewRouter(svc *service.EventService, apiKey string) *chi.Mux {
	r := chi.NewRouter()

	// Global middleware
	r.Use(metrics.InstrumentHandler)
	r.Use(middleware.RequestID)
	// TODO: middleware.RealIP is deprecated — trusts XFF header blindly, enabling IP spoofing.
	// Replace with a right-to-left XFF traversal that only accepts IPs from a known
	// proxy allowlist. See: github.com/go-chi/chi/security/advisories/GHSA-3fxj-6jh8-hvhx
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Handlers
	healthHandler := handlers.NewHealthHandler()
	eventHandler := handlers.NewEventHandler(svc)
	analysisHandler := handlers.NewAnalysisHandler(svc)

	// Public routes
	r.Get("/health", healthHandler.Health)
	r.Handle("/metrics", promhttp.Handler())

	// Protected routes
	r.Group(func(r chi.Router) {
		r.Use(auth.APIKeyMiddleware(apiKey))

		r.Post("/events", eventHandler.CreateEvent)
		r.Get("/events", eventHandler.ListEvents)

		r.Get("/analysis/suspicious-ips", analysisHandler.SuspiciousIPs)
		r.Get("/analysis/user-activity", analysisHandler.UserActivity)
	})

	return r
}
