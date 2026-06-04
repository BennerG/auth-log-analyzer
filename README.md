# auth-log-analyzer

A Go REST API for ingesting and analyzing authentication events. Detects suspicious login patterns—failed login spikes, IPs targeting multiple accounts, and anomalous user activity—across a configurable time window.

## Features

- Ingest authentication events via REST API (logins, logouts, token lifecycle, failed attempts)
- Detect suspicious IPs: failed login spikes above a configurable threshold across a time window
- Summarize user activity: event counts, failure rates, and unique IPs per user
- API key authentication middleware with clear 401/403 semantics
- Prometheus metrics: HTTP request counts, latency histograms, and domain-level event counters
- Structured JSON logging via zerolog (pretty-printed in development, JSON in production)
- Raw SQL via pgx (no ORM) enabling full control over queries and indexes

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

```bash
git clone https://github.com/BennerG/auth-log-analyzer.git
cd auth-log-analyzer
```

Copy the example env file and configure your values:

```bash
cp .env.example .env
```

Start the PostgreSQL and Redis containers:

```bash
docker-compose up -d
```

Run the database migration:

```bash
export DATABASE_URL="postgres://postgres:postgres@localhost:5432/auth_log_analyzer?sslmode=disable"
make migrate
```

Start the server:

```bash
make dev
```

You should see:

```
INF database connection pool established
INF server starting port=8080
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

All endpoints except `/health` and `/metrics` require an `Authorization: Bearer <api-key>` header.

| Method | Path                       | Auth     | Description                                     |
| ------ | -------------------------- | -------- | ----------------------------------------------- |
| GET    | `/health`                  | None     | Service health check                            |
| GET    | `/metrics`                 | None     | Prometheus metrics scrape endpoint              |
| POST   | `/events`                  | Required | Ingest a new authentication event               |
| GET    | `/events`                  | Required | List recent events, optionally filtered by user |
| GET    | `/analysis/suspicious-ips` | Required | IPs with failed logins above threshold          |
| GET    | `/analysis/user-activity`  | Required | Per-user event counts and failure rates         |

#### POST `/events`

| Field        | Type   | Required | Description                                                                                                    |
| ------------ | ------ | -------- | -------------------------------------------------------------------------------------------------------------- |
| `user_id`    | string | Yes      | Identifier of the user                                                                                         |
| `ip_address` | string | Yes      | IPv4 or IPv6 address                                                                                           |
| `event_type` | string | Yes      | One of: `login`, `logout`, `failed_login`, `token_issued`, `token_refresh`, `token_revoked`, `password_change` |
| `status`     | string | Yes      | One of: `success`, `failure`, `blocked`                                                                        |
| `user_agent` | string | No       | HTTP User-Agent string                                                                                         |

#### GET `/events`

| Param     | Type   | Default | Description                          |
| --------- | ------ | ------- | ------------------------------------ |
| `user_id` | string | —       | Filter events to a specific user     |
| `limit`   | int    | 50      | Max results returned (capped at 100) |

#### GET `/analysis/suspicious-ips`

| Param         | Type | Default | Description                           |
| ------------- | ---- | ------- | ------------------------------------- |
| `threshold`   | int  | 5       | Minimum failed attempts to flag an IP |
| `since_hours` | int  | 24      | Lookback window in hours              |

#### GET `/analysis/user-activity`

| Param         | Type | Default | Description              |
| ------------- | ---- | ------- | ------------------------ |
| `since_hours` | int  | 24      | Lookback window in hours |

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
    "ip_address": "192.168.1.1",
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

# Scrape Prometheus Metrics
curl localhost:8080/metrics
```

## Design Descisions

- PostgreSQL `INET` type used for `ip_address`. This type validates IP format at the DB
  layer and enables subnet queries (`<<` operator) without application-level parsing.
  Requires `::TEXT` cast in `RETURNING` and `SELECT` clauses when scanning into Go
  strings via pgx.
- `host(ip_address)` used instead of `ip_address::TEXT` in `RETURNING` and `SELECT`
  clauses. Postgres normalizes `INET` values to include a CIDR prefix on cast
  (e.g. `192.168.1.1` to `192.168.1.1/32`), which breaks string comparisons.
  `host()` strips the prefix and returns just the address, keeping IP strings
  clean for API consumers without requiring post-processing in Go.
- `middleware.RealIP` removed after discovering CVE (GHSA-3fxj-6jh8-hvhx).
  Blind XFF trust enables IP spoofing. Production implementation should traverse
  XFF right-to-left against a known proxy allowlist.
- zerolog chosen over the standard `log` package for structured, queryable JSON output
  in production and pretty-printed console output in development. The same logger
  utilizes different writers per environment. Zero allocations on the hot path.

## What's Next

- **Rate limiting** — per-IP request throttling using Redis to complement the suspicious IP detection
- **JWT authentication** — replace static API key with signed JWT tokens, scoped per user with expiry and revocation
- **gRPC endpoint** — expose event ingestion and analysis via a gRPC API alongside the existing REST layer
- **Alerting** — webhook or email notification when an IP crosses the suspicious threshold in real time
- **XFF middleware** — production-safe `X-Forwarded-For` parsing traversing right-to-left against a known proxy allowlist, replacing the deprecated `middleware.RealIP`
- **OpenTelemetry tracing** — distributed trace context propagation across the request lifecycle
