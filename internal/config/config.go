package config

import (
	"log"
	"os"
	"strconv"

	"github.com/BennerG/auth-log-analyzer/internal/api"
)

type Config struct {
	Port        string
	Env         string
	DatabaseURL string
	APIKey      string
	RedisURL    string

	// Rate limits (requests per minute per IP)
	IngestLimit   int // POST /events writes to Postgres
	EventsLimit   int // GET /events reads events for dashboard polling
	AnalysisLimit int // Get /analysis/* reads after aggregation queries
}

func Load() *Config {
	cfg := &Config{
		Port:          getEnv("PORT", "8080"),
		Env:           getEnv("ENV", "development"),
		DatabaseURL:   getEnv("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/auth_log_analyzer?sslmode=disable"),
		APIKey:        getEnv("API_KEY", "dev-secret-key-change-in-prod"),
		RedisURL:      getEnv("REDIS_URL", "redis://localhost:6379"),
		IngestLimit:   getEnvInt("RATE_LIMIT_INGEST", 30),
		EventsLimit:   getEnvInt("RATE_LIMIT_EVENTS", 120),
		AnalysisLimit: getEnvInt("RATE_LIMIT_ANALYSIS", 30),
	}

	if cfg.DatabaseURL == "" {
		log.Fatal("DATABASE_URL is required")
	}
	if cfg.APIKey == "" {
		log.Fatal("API_KEY is required")
	}

	return cfg
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

func (c *Config) RateLimitConfig() api.RateLimitConfig {
	return api.RateLimitConfig{
		IngestLimit:   c.IngestLimit,
		EventsLimit:   c.EventsLimit,
		AnalysisLimit: c.AnalysisLimit,
	}
}
