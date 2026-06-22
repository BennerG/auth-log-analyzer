package ratelimit

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/redis/go-redis/v9"
)

func New(rdb *redis.Client, limit int, window time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			ip, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				ip = r.RemoteAddr
			}

			allowed, remaining, reset, err := check(ctx, rdb, ip, limit, window, time.Now())
			if err != nil {
				// allow requests to pass through if redis is down
				next.ServeHTTP(w, r)
				return
			}

			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(limit))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(reset, 10))

			if !allowed {
				w.Header().Set("Retry-After", strconv.FormatInt(reset-time.Now().Unix(), 10))
				http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// check runs the sliding window logic against Redis
// Returns: allowed, remaining, reset (unix timestamp), error
func check(ctx context.Context, rdb *redis.Client, ip string, limit int, window time.Duration, now time.Time) (bool, int, int64, error) {
	windowStart := now.Add(-window)
	resetAt := now.Add(window).Unix()

	key := fmt.Sprintf("ratelimit:%s", ip)

	pipe := rdb.Pipeline()

	// Remove entries older than the window
	pipe.ZRemRangeByScore(ctx, key, "0", strconv.FormatInt(windowStart.UnixMicro(), 10))

	// Count remaining entries in window
	countCmd := pipe.ZCard(ctx, key)

	// Add this request: score = now in microseconds | member = requestID:timestamp
	reqID := middleware.GetReqID(ctx)
	member := fmt.Sprintf("%s:%d", reqID, now.UnixMicro())
	pipe.ZAdd(ctx, key, redis.Z{
		Score:  float64(now.UnixMicro()),
		Member: member,
	})

	// Auto-expire the key after 2x window to nix stale keys
	pipe.Expire(ctx, key, window*2)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return false, 0, 0, fmt.Errorf("ratelimit: redis pipeline: %w", err)
	}

	count := countCmd.Val()
	remaining := limit - int(count) - 1
	if remaining < 0 {
		remaining = 0
	}

	allowed := count < int64(limit)
	return allowed, remaining, resetAt, nil
}
