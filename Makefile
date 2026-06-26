.PHONY: dev build test test-grpc migrate vet lint

dev:
	docker-compose up -d
	go run ./cmd/server

build:
	go build -o auth-log-analyzer ./cmd/server

test:
	go test ./... -race

test-grpc:
	go test ./internal/grpc/... -v -race

migrate:
	psql $(DATABASE_URL) -f internal/db/migrations/001_init.sql

vet:
	go vet ./...

lint:
	golangci-lint run ./...