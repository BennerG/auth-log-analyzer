.PHONY: dev build test migrate lint

dev:
	docker-compose up -d
	go run ./cmd/server

build:
	go build -o auth-log-analyzer ./cmd/server

test:
	go test ./...

migrate:
	psql $(DATABASE_URL) -f internal/db/migrations/001_init.sql

lint:
	golangci-lint run ./...