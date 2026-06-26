# auth-log-analyzer

A Go REST and gRPC API for ingesting and analyzing authentication events. Detects suspicious login patterns—failed login spikes, IPs targeting multiple accounts, and anomalous user activity—across a configurable time window.

## Features

- Ingest authentication events via REST API or gRPC (logins, logouts, token lifecycle, failed attempts)
- Detect suspicious IPs: failed login spikes above a configurable threshold across a time window
- Summarize user activity: event counts, failure rates, and unique IPs per user
- RS256 JWT authentication with signed tokens containing sub, exp, iat, jti, and role claims
- Token issuance via POST /auth/login with constant-time credential comparison to prevent timing attacks
- JWT verified on both REST (HTTP middleware) and gRPC (unary and stream interceptors) using the same RSA key pair
- Per-IP sliding window rate limiting via Redis with configurable per-route limits and standard rate limit response headers
- gRPC server-streaming RPC: suspicious IP results streamed row-by-row without buffering the full result set
- Prometheus metrics: HTTP request counts, latency histograms, and domain-level event counters
- Structured JSON logging via zerolog with per-request log lines on both REST and gRPC transports
- Raw SQL via pgx (no ORM) enabling full control over queries and indexes

## Architecture

### System Components

Requests arrive on two ports: REST on `:8080` via Chi, gRPC on `:9090`. Both share the same PostgreSQL pool and RSA key pair. Redis is used exclusively for REST rate limiting.

```mermaid
flowchart LR
    postgres[("PostgreSQL")]
    redis[("Redis")]

    subgraph REST [:8080]
        ChiRouter --> RateLimiter --> JWTMiddleware --> RESTHandler
    end

    subgraph gRPC [:9090]
        gRPCServer --> LoggingInterceptor --> JWTInterceptor --> GRPCHandler
    end

    RESTHandler --> Service --> postgres
    GRPCHandler --> Service
    RateLimiter --> redis
```

### Request Flow

#### REST: authenticated POST /events

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

#### gRPC: StreamSuspiciousIPs

```mermaid
sequenceDiagram
    Client->>gRPCServer: StreamSuspiciousIPs (metadata: authorization Bearer)
    gRPCServer->>LoggingInterceptor: record method and peer IP
    LoggingInterceptor->>JWTInterceptor: extract token from metadata
    JWTInterceptor-->>Client: Unauthenticated if missing or invalid
    JWTInterceptor->>GRPCHandler: verified claims in context
    GRPCHandler->>PostgreSQL: SELECT ... GROUP BY ip_address
    loop one message per row
        GRPCHandler-->>Client: stream.Send(SuspiciousIPResult)
    end
    GRPCHandler-->>Client: stream closed
```

## Quick Start

### Prerequisites

- Go 1.22+
- Docker + docker-compose
- PostgreSQL client 16+
- buf 1.55+ (for regenerating protobuf code)

### Setup

```bash
# 1. Clone the repo
git clone https://github.com/BennerG/auth-log-analyzer.git
cd auth-log-analyzer

# 2. Copy the example env file and configure your values
cp .env.example .env

# 3. Start the PostgreSQL and Redis containers
docker-compose up -d

# 4. Run the database migration
export DATABASE_URL="postgres://postgres:postgres@localhost:5432/auth_log_analyzer?sslmode=disable"
make migrate

# 5. Start the server
make dev

# You should see:
# INF database connection pool established
# INF redis connection established
# INF HTTP server starting port=8080
# INF gRPC server starting port=9090
```

### Regenerating protobuf code

```bash
buf generate
```

Generated files land in `gen/authlog/v1/`. Never edit them directly.

## API Reference

### Authentication

All protected endpoints require a signed JWT in the `Authorization` header (REST) or `authorization` metadata key (gRPC):

```bash
Authorization: Bearer <jwt>
```

Tokens are issued at `POST /auth/login` and signed with RS256 using a 2048-bit RSA private key. Each token carries `sub`, `exp`, `iat`, `jti`, and `role` claims. The `jti` claim is a unique token ID included to support a future revocation store.

Tokens expire after 15 minutes by default, configurable via `JWT_EXPIRY`.

The same token works for both REST and gRPC — both transports verify against the same RSA public key.

### Rate Limiting (REST only)

Protected REST endpoints are rate limited per IP using a sliding window algorithm backed by Redis.

| Endpoint          | Limit       |
| ----------------- | ----------- |
| `POST /events`    | 30 req/min  |
| `GET /events`     | 120 req/min |
| `GET /analysis/*` | 30 req/min  |

Rate limit headers are returned on every response:

```bash
X-RateLimit-Limit: 30
X-RateLimit-Remaining: 17
X-RateLimit-Reset: 1719043200
Retry-After: 47  (429 responses only)
```

Requests pass through if Redis is unavailable (fail open).

### REST Endpoints

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

### gRPC Endpoints (port 9090)

Proto definition: `proto/authlog/v1/authlog.proto`

| RPC                   | Type             | Auth     | Description                                     |
| --------------------- | ---------------- | -------- | ----------------------------------------------- |
| `IngestEvent`         | Unary            | Required | Record a single authentication event            |
| `StreamSuspiciousIPs` | Server streaming | Required | Stream suspicious IPs above a failure threshold |

#### IngestEvent

Request fields:

| Field        | Type   | Required | Description                          |
| ------------ | ------ | -------- | ------------------------------------ |
| `user_id`    | string | Yes      | Identifier of the user               |
| `ip_address` | string | Yes      | IPv4 or IPv6 address                 |
| `event_type` | string | Yes      | e.g. `failed_login`, `login_success` |

Response: `event_id` (assigned by server) and `message`.

#### StreamSuspiciousIPs

Request fields:

| Field          | Type  | Default | Description                            |
| -------------- | ----- | ------- | -------------------------------------- |
| `min_failures` | int32 | 5       | Minimum failure count to include an IP |

Each streamed message contains `ip_address`, `failure_count`, `unique_users`, and `last_seen`.

## Local Development

### Running Tests

```bash
# All packages
go test ./... -race

# Auth package only (JWT, middleware, gRPC interceptors)
go test ./internal/auth/... -v -race

# gRPC handlers (requires auth_log_analyzer_test database: see below)
go test ./internal/grpc/... -v -race
```

The gRPC handler tests connect to a real PostgreSQL instance. Create the test database before running:

```bash
# Override the default DSN via environment variable if needed
TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/auth_log_analyzer_test?sslmode=disable

# Create test database
psql $TEST_DATABASE_URL -c "CREATE DATABASE auth_log_analyzer_test;"

# Then, run gRPC tests
go test ./internal/grpc/... -v -race
```

### PostgreSQL Commands

```bash
export DATABASE_URL=postgres://postgres:postgres@localhost:5432/auth_log_analyzer?sslmode=disable

# Inspect the auth_events table
psql $DATABASE_URL -c "\d auth_events"

# Check for entries
psql $DATABASE_URL -c "SELECT * FROM auth_events"
```

### Redis Test

```bash
# Fire 35 requests at POST /events to exceed the 30/min limit
for i in $(seq 1 35); do
  echo -n "Request $i: "
  curl -s -o /dev/null -w "%{http_code}" -X POST http://localhost:8080/events \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"user_id":"user-123","ip_address":"192.168.1.1","event_type":"failed_login","status":"failure","user_agent":"Mozilla/5.0"}'
  echo
done

# Send a single request and verify rate limit headers
curl -v -X POST http://localhost:8080/events \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"user-123","ip_address":"192.168.1.1","event_type":"failed_login","status":"failure","user_agent":"Mozilla/5.0"}' \
  2>&1 | grep -E "X-RateLimit|Retry-After|< HTTP"
```

### curl Commands

```bash
# Public (no auth needed)
curl localhost:8080/health

# Simulate login and capture JWT (no auth needed)
TOKEN=$(curl -s -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"dev-password-change-in-prod"}' \
  | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

echo $TOKEN

# Ingest an event
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

# Prometheus metrics (no auth needed)
curl localhost:8080/metrics
```

### grpcurl Commands

```bash
# Obtain a token from the REST login endpoint
TOKEN=$(curl -s -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"dev-password-change-in-prod"}' \
  | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

# Ingest an event
grpcurl -plaintext -import-path proto -proto authlog/v1/authlog.proto \
  -H "authorization: Bearer $TOKEN" \
  -d '{"user_id": "user-234", "ip_address": "192.168.1.100", "event_type": "failed_login"}' \
  localhost:9090 authlog.v1.AuthLogService/IngestEvent

# Stream suspicious IPs (results arrive as separate JSON objects)
grpcurl -plaintext -import-path proto -proto authlog/v1/authlog.proto \
  -H "authorization: Bearer $TOKEN" \
  -d '{"min_failures": 1}' \
  localhost:9090 authlog.v1.AuthLogService/StreamSuspiciousIPs

# Unauthenticated request — returns Unauthenticated error
grpcurl -plaintext -import-path proto -proto authlog/v1/authlog.proto \
  -d '{"min_failures": 1}' \
  localhost:9090 authlog.v1.AuthLogService/StreamSuspiciousIPs
```

## Design Decisions

- **Two transports, one service layer.** REST and gRPC handlers both call into the same `EventService`. No logic is duplicated. The transport layer handles serialization and auth, and the service layer owns the queries.
- **gRPC server streaming for analysis results.** `StreamSuspiciousIPs` sends one message per row rather than collecting all results into a slice before responding. For large datasets, this reduces time-to-first-byte and eliminates the memory spike of buffering the full result set.
- **JWT interceptor in the `auth` package.** The gRPC interceptors live alongside the HTTP middleware in `internal/auth` so they share the unexported `claimsKey` context key. Both transports call `auth.ClaimsFromContext(ctx)` identically, and a single RSA key pair is loaded once at startup.
- **Logging interceptor runs before JWT.** Auth failures are always logged including the peer IP and method name, which is useful for detecting brute force attempts against the gRPC endpoints.
- **PostgreSQL `INET` type** used for `ip_address`. This type validates IP format at the DB layer and enables subnet queries (`<<` operator) without application-level parsing. Requires `host()` in SELECT clauses to strip the CIDR prefix that Postgres adds on cast.
- **`host(ip_address)`** used instead of `ip_address::TEXT`. Postgres normalizes `INET` values to include a CIDR prefix on cast (e.g. `192.168.1.1/32`), which breaks string comparisons. `host()` strips the prefix and returns just the address.
- **`middleware.RealIP` to be removed** after discovering CVE (GHSA-3fxj-6jh8-hvhx). Blind XFF trust enables IP spoofing. Production implementation should traverse XFF right-to-left against a known proxy allowlist.
- **zerolog** chosen over the standard `log` package for structured, queryable JSON output in production and pretty-printed console output in development. Zero allocations on the hot path.
- **Sliding window rate limiting** chosen over fixed window. Fixed window has a boundary exploit where a client can send 2x the limit by hitting the tail of one window and the head of the next. Sliding window via Redis sorted sets eliminates this.
- **RS256 chosen over HS256** for JWT signing. Asymmetric keys mean the verification key can be distributed publicly without exposing the signing key. This is the foundation of JWKS endpoints used in production identity providers.
- **Constant-time credential comparison** in the login handler prevents timing attacks. A naive string comparison returns early on the first mismatched byte, allowing an attacker to infer correct characters by measuring response latency.

## What's Next

- **JWT revocation store** — Redis set of revoked `jti` values checked on every request, enabling token invalidation before expiry
- **Rate limiting on POST /auth/login** — brute force protection on the login endpoint itself
- **Rate limiting on gRPC endpoints** — per-IP sliding window applied via a gRPC interceptor, mirroring the REST rate limiter
- **Alerting** — webhook or email notification when an IP crosses the suspicious threshold in real time
- **XFF middleware** — production-safe `X-Forwarded-For` parsing traversing right-to-left against a known proxy allowlist
- **OpenTelemetry tracing** — distributed trace context propagation across both REST and gRPC request lifecycles
