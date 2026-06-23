# auth-log-analyzer

A Go REST API for ingesting and analyzing authentication events. Detects suspicious login patterns—failed login spikes, IPs targeting multiple accounts, and anomalous user activity—across a configurable time window.

## Features

- Ingest authentication events via REST API (logins, logouts, token lifecycle, failed attempts)
- Detect suspicious IPs: failed login spikes above a configurable threshold across a time window
- Summarize user activity: event counts, failure rates, and unique IPs per user
- RS256 JWT authentication with signed tokens containing sub, exp, iat, jti, and role claims
- Token issuance via POST /auth/login with constant-time credential comparison to prevent timing attacks
- Per-IP sliding window rate limiting via Redis with configurable per-route limits and standard rate limit response headers
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
    Client->>Router: POST /auth/login
    Router->>AuthHandler: validate credentials
    AuthHandler-->>Client: 401 if invalid
    AuthHandler-->>Client: 200 with signed JWT

    Client->>Router: POST /events
    Router->>RateLimiter: check sliding window
    RateLimiter-->>Client: 429 if limit exceeded
    RateLimiter->>JWTMiddleware: pass through
    JWTMiddleware-->>Client: 401 if invalid or expired token
    JWTMiddleware->>Handler: verified claims in context
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
# 1. clone the repo
git clone https://github.com/BennerG/auth-log-analyzer.git
cd auth-log-analyzer

# 2. Copy the example env file and configure your values:
cp .env.example .env

# 3. Start the PostgreSQL and Redis containers:
docker-compose up -d

# 4. Run the database migration:
export DATABASE_URL="postgres://postgres:postgres@localhost:5432/auth_log_analyzer?sslmode=disable"
make migrate

# 5. Start the server:
make dev

# You should see:
INF database connection pool established
INF server starting port=8080
```

## API Reference

### Authentication and Rate Limiting

Protected endpoints require a signed JWT in the `Authorization` header:

```
Authorization: Bearer <jwt>
```

Tokens are issued at `POST /auth/login` and signed with RS256 using a 2048-bit RSA private key. Each token carries `sub`, `exp`, `iat`, `jti`, and `role` claims. The `jti` claim is a unique token ID included to support a future revocation store.

Tokens expire after 15 minutes by default, configurable via `JWT_EXPIRY`.

Protected endpoints are rate limited per IP using a sliding window algorithm backed by Redis. Limits are configurable via environment variables.

| Endpoint          | Limit       |
| ----------------- | ----------- |
| `POST /events`    | 30 req/min  |
| `GET /events`     | 120 req/min |
| `GET /analysis/*` | 30 req/min  |

Rate limit headers are returned on every response:

```
X-RateLimit-Limit: 30
X-RateLimit-Remaining: 17
X-RateLimit-Reset: 1719043200
Retry-After: 47  (429 responses only)
```

Requests pass through if Redis is unavailable (fail open).

### Endpoints

All endpoints except `/health` and `/metrics` require an `Authorization: Bearer <api-key>` header.

| Method | Path                       | Auth     | Description                                     |
| ------ | -------------------------- | -------- | ----------------------------------------------- |
| GET    | `/health`                  | None     | Service health check                            |
| GET    | `/metrics`                 | None     | Prometheus metrics scrape endpoint              |
| POST   | `/auth/login`              | None     | Issue a signed RS256 JWT                        |
| POST   | `/events`                  | Required | Ingest a new authentication event               |
| GET    | `/events`                  | Required | List recent events, optionally filtered by user |
| GET    | `/analysis/suspicious-ips` | Required | IPs with failed logins above threshold          |
| GET    | `/analysis/user-activity`  | Required | Per-user event counts and failure rates         |

#### POST `/auth/login`

| Field      | Type   | Required | Description    |
| ---------- | ------ | -------- | -------------- |
| `username` | string | Yes      | Admin username |
| `password` | string | Yes      | Admin password |

Response:

```json
{
  "token": "eyJhbGci...",
  "expires_at": "2026-06-22T17:45:00Z"
}
```

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

### Redis Test

```bash
# Fire 35 requests at POST /events to break the 30/min limit
for i in $(seq 1 35); do
  echo -n "Request $i: "
  curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:8080/events \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"user_id":"user-123","ip_address":"192.168.1.1","event_type":"failed_login","status":"failure","user_agent":"Mozilla/5.0"}'
  echo
done

# Send of single request and verify new headers
curl -v -X POST http://localhost:8080/events \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"user-123","ip_address":"192.168.1.1","event_type":"failed_login","status":"failure","user_agent":"Mozilla/5.0"}' \
  2>&1 | grep -E "X-RateLimit|Retry-After|< HTTP"
```

### curl Commands

```bash
# Public — no auth needed
curl localhost:8080/health

# Missing auth examples that return 401
curl localhost:8080/events

curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/events

curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/events \
  -H "Authorization: Bearer thisisnotavalidtoken"

# Simulate login and capture JWT
TOKEN=$(curl -s -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"dev-password-change-in-prod"}' \
  | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

echo $TOKEN

# Create an event
curl -s -X POST http://localhost:8080/events \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"user-123","ip_address":"192.168.1.1","event_type":"failed_login","status":"failure","user_agent":"Mozilla/5.0"}'

# List events
curl localhost:8080/events \
  -H "Authorization: Bearer $TOKEN"

# Analysis
curl "localhost:8080/analysis/suspicious-ips?threshold=1" \
  -H "Authorization: Bearer $TOKEN"

curl "localhost:8080/analysis/user-activity?since_hours=48" \
  -H "Authorization: Bearer $TOKEN"

# Scrape Prometheus Metrics
curl localhost:8080/metrics
```

## Design Decisions

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
- Sliding window chosen over fixed window for rate limiting. Fixed window has a boundary exploit where a client can send 2x the limit by hitting the tail of one window and the head of the next. Sliding window via Redis sorted sets eliminates this. Each request is scored by timestamp, old entries are trimmed on every check, and the window moves continuously with time. All Redis commands run in a single pipeline to avoid multiple round trips per request.
- RS256 chosen over HS256 for JWT signing. Asymmetric keys mean the verification key can be distributed publicly without exposing the signing key. This is the foundation of JWKS endpoints used in production identity providers and is directly relevant to certificate-based auth systems.
- Constant-time credential comparison used in the login handler to prevent timing attacks. A naive string comparison returns early on the first mismatched byte, allowing an attacker to infer correct characters by measuring response latency across many requests. The constant-time implementation always iterates every byte regardless of where strings diverge.

## What's Next

- **JWT revocation store** — Redis set of revoked jti values checked on every request, enabling token invalidation before expiry
- **Rate limiting on POST /auth/login** — brute force protection on the login endpoint itself
- **gRPC endpoint** — expose event ingestion and analysis via a gRPC API alongside the existing REST layer
- **Alerting** — webhook or email notification when an IP crosses the suspicious threshold in real time
- **XFF middleware** — production-safe `X-Forwarded-For` parsing traversing right-to-left against a known proxy allowlist, replacing the deprecated `middleware.RealIP`
- **OpenTelemetry tracing** — distributed trace context propagation across the request lifecycle
