package config

import (
	"log"
	"os"
	"strconv"
	"time"

	"github.com/BennerG/auth-log-analyzer/internal/api"
)

type Config struct {
	Port        string
	Env         string
	DatabaseURL string
	RedisURL    string

	// JWT
	JWTPrivateKeyPath string
	JWTPublicKeyPath  string
	JWTExpiry         time.Duration

	// Admin credentials for POST /auth/login
	AdminUsername string
	AdminPassword string

	// Rate limits (requests per minute per IP)
	IngestLimit   int // POST /events writes to Postgres
	EventsLimit   int // GET /events reads for dashboard polling
	AnalysisLimit int // GET /analysis/* aggregation queries
}

func Load() *Config {
	cfg := &Config{
		Port:              getEnv("PORT", "8080"),
		Env:               getEnv("ENV", "development"),
		DatabaseURL:       getEnv("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/auth_log_analyzer?sslmode=disable"),
		RedisURL:          getEnv("REDIS_URL", "redis://localhost:6379"),
		JWTPrivateKeyPath: getEnv("JWT_PRIVATE_KEY_PATH", "keys/private.pem"),
		JWTPublicKeyPath:  getEnv("JWT_PUBLIC_KEY_PATH", "keys/public.pem"),
		JWTExpiry:         getEnvDuration("JWT_EXPIRY", 15*time.Minute),
		AdminUsername:     getEnv("ADMIN_USERNAME", "admin"),
		AdminPassword:     getEnv("ADMIN_PASSWORD", "dev-password-change-in-prod"),
		IngestLimit:       getEnvInt("RATE_LIMIT_INGEST", 30),
		EventsLimit:       getEnvInt("RATE_LIMIT_EVENTS", 120),
		AnalysisLimit:     getEnvInt("RATE_LIMIT_ANALYSIS", 30),
	}

	if cfg.DatabaseURL == "" {
		log.Fatal("DATABASE_URL is required")
	}
	if cfg.AdminPassword == "" {
		log.Fatal("ADMIN_PASSWORD is required")
	}
	if cfg.JWTPrivateKeyPath == "" {
		log.Fatal("JWT_PRIVATE_KEY_PATH is required")
	}
	if cfg.JWTPublicKeyPath == "" {
		log.Fatal("JWT_PUBLIC_KEY_PATH is required")
	}

	return cfg
}

func (c *Config) RateLimitConfig() api.RateLimitConfig {
	return api.RateLimitConfig{
		IngestLimit:   c.IngestLimit,
		EventsLimit:   c.EventsLimit,
		AnalysisLimit: c.AnalysisLimit,
	}
}

func getEnv(key, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultVal
}

func getEnvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}
