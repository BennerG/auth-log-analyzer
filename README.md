# auth-log-analyzer

A Go REST API for ingesting an analysing authentication events. Detects suspicious login patterns—failed login spikes, IPs targeting multiple accounts, and anomalous user activity—across a configurable time window.

## Features

## Architecture

### System Components

Requests flow through a Chi router into an API key middleware chain before
reaching the handler and service layers. PostgreSQL is the sole persistence
layer—no ORM, raw SQL via pgx.

```mermaid
flowchart LR
    postgres[("PostgreSQL")]
    Client --> Router --> Middleware --> Handler --> Service --> postgres
```

### Request Flow

The sequence below shows an authenticated `POST /events` request. Requests
with a missing or invalid Bearer token are rejected at the middleware layer
and never reach the handler.

```mermaid
sequenceDiagram
    Client->>Router: POST /events
    Router->>Middleware: validate Bearer token
    Middleware-->>Client: 401 if invalid
    Middleware->>Handler: authorized request
    Handler->>Service: CreateEvent()
    Service->>PostgreSQL: INSERT ... RETURNING
    PostgreSQL-->>Service: AuthEvent
    Service-->>Handler: *AuthEvent
    Handler-->>Client: 201 created
```

## Quick Start

### Prerequisites

- Go 1.22+
- Docker + docker-compose
- PostgreSQL Client 16+

### Setup

```
git clone https://github.com/BennerG/auth-log-analyzer.git
```

Ensure that you have a Docker engine running to create the PostgreSQL database and Redis cache.

Then, run:

```
make dev
```

In your terminal, you should see:

```
database connection pool established
server listenting on :port-you-configured-in-env
```

## API Reference

### Authentication

All protected endppoints require a Bearer token in the `Authorization` header:

```
Authorization: Bearer <api-key>
```

Incoming requests pass through an API Key middleware that extracts the token from the header and compares it against a static key loaded at server startup from the `API_KEY` environment variable.

This is intentionally simple for a portfolio project. In production, you would replace the static key comparison with a lookup against a database or cache, where each key is scoped to a specific user or service, supports rotation, and can be revoked independently.

### Endpoints

## Local Development

### PostgreSQL Commands

```bash
# Set shell environment variable
DATABASE_URL=postgres://postgres:postgres@localhost:5432/auth_log_analyzer?sslmode=disable

# Check that auth_events table
psql $DATABASE_URL -c "\d auth_events"

# Check for entries in auth_events
psql $DATABASE_URL -c "SELECT * FROM auth_events"
```

### curl Commands

```bash
# Public — no auth needed
curl localhost:8080/health

# Missing auth — should return 401
curl localhost:8080/events

# Create an event
curl -X POST localhost:8080/events \
  -H "Authorization: Bearer dev-secret-key-change-in-prod" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "user-123",
    "ip_address": "192.168.1.3",
    "event_type": "failed_login",
    "status": "failure",
    "user_agent": "Mozilla/5.0"
  }'

# List events
curl localhost:8080/events \
  -H "Authorization: Bearer dev-secret-key-change-in-prod"

# Analysis
curl "localhost:8080/analysis/suspicious-ips?threshold=1" \
  -H "Authorization: Bearer dev-secret-key-change-in-prod"

curl "localhost:8080/analysis/user-activity?since_hours=48" \
  -H "Authorization: Bearer dev-secret-key-change-in-prod"
```

## Design Descisions

- PostgreSQL `INET` type used for `ip_address` — validates IP format at the DB
  layer and enables subnet queries (`<<` operator) without application-level parsing.
  Requires `::TEXT` cast in `RETURNING` and `SELECT` clauses when scanning into Go
  strings via pgx.
- `host(ip_address)` used instead of `ip_address::TEXT` in `RETURNING` and `SELECT`
  clauses — Postgres normalizes `INET` values to include a CIDR prefix on cast
  (e.g. `192.168.1.1` → `192.168.1.1/32`), which breaks string comparisons.
  `host()` strips the prefix and returns just the address, keeping IP strings
  clean for API consumers without requiring post-processing in Go.
- `middleware.RealIP` removed after discovering CVE (GHSA-3fxj-6jh8-hvhx).
  Blind XFF trust enables IP spoofing. Production implementation should traverse
  XFF right-to-left against a known proxy allowlist.

## What's Next
