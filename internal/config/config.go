package config

import (
	"log"
	"os"
)

type Config struct {
	Port        string
	Env         string
	DatabaseURL string
	APIKey      string
	RedisURL    string
}

func Load() *Config {
	cfg := &Config{
		Port:        getEnv("PORT", "8080"),
		Env:         getEnv("ENV", "development"),
		DatabaseURL: getEnv("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/auth_log_analyzer?sslmode=disable"),
		APIKey:      getEnv("API_KEY", "dev-secret-key-change-in-prod"),
		RedisURL:    getEnv("REDIS_URL", "redis://localhost:6379"),
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
