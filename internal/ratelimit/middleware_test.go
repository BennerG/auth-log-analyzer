package ratelimit

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newTestRedis(t *testing.T) (*redis.Client, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	t.Cleanup(mr.Close)

	rdb := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	t.Cleanup(func() { rdb.Close() })

	return rdb, mr
}

func TestCheck(t *testing.T) {
	tests := []struct {
		name          string
		limit         int
		window        time.Duration
		requests      int           // how many requests to fire before the assertion request
		fastForward   time.Duration // how much to advance miniredis clock before assertion
		wantAllowed   bool
		wantRemaining int
	}{
		{
			name:          "first request is allowed",
			limit:         5,
			window:        time.Minute,
			requests:      0,
			wantAllowed:   true,
			wantRemaining: 4,
		},
		{
			name:          "requests under limit are allowed",
			limit:         5,
			window:        time.Minute,
			requests:      3,
			wantAllowed:   true,
			wantRemaining: 1,
		},
		{
			name:          "request at exactly the limit is blocked",
			limit:         5,
			window:        time.Minute,
			requests:      5,
			wantAllowed:   false,
			wantRemaining: 0,
		},
		{
			name:          "request beyond the limit is blocked",
			limit:         5,
			window:        time.Minute,
			requests:      10,
			wantAllowed:   false,
			wantRemaining: 0,
		},
		{
			name:          "remaining hits zero and stays there",
			limit:         3,
			window:        time.Minute,
			requests:      4,
			wantAllowed:   false,
			wantRemaining: 0,
		},
		{
			name:          "old entries outside window are ignored",
			limit:         5,
			window:        time.Minute,
			requests:      5,                         // fill the window
			fastForward:   time.Minute + time.Second, // advance past the window
			wantAllowed:   true,                      // old entries dropped, this is a fresh window
			wantRemaining: 4,
		},
		{
			name:          "single request limit blocks on second request",
			limit:         1,
			window:        time.Minute,
			requests:      1,
			wantAllowed:   false,
			wantRemaining: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rdb, _ := newTestRedis(t)
			ctx := context.Background()
			ip := "127.0.0.1"

			// Fire the setup requests
			now := time.Now()
			for i := 0; i < tt.requests; i++ {
				_, _, _, err := check(ctx, rdb, ip, tt.limit, tt.window, time.Now())
				if err != nil {
					t.Fatalf("setup request %d failed: %v", i+1, err)
				}
			}

			// // Advance miniredis clock if needed (simulates time passing)
			// if tt.fastForward > 0 {
			// 	mr.FastForward(tt.fastForward)
			// }
			assertNow := now.Add(tt.fastForward)

			// Assertion request
			allowed, remaining, reset, err := check(ctx, rdb, ip, tt.limit, tt.window, assertNow)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if allowed != tt.wantAllowed {
				t.Errorf("allowed = %v, want %v", allowed, tt.wantAllowed)
			}
			if remaining != tt.wantRemaining {
				t.Errorf("remaining = %v, want %v", remaining, tt.wantRemaining)
			}

			// reset should always be in the future
			if reset <= time.Now().Unix() {
				t.Errorf("reset timestamp %v should be in the future", reset)
			}
		})
	}
}

func TestCheckIsolation(t *testing.T) {
	// Different IPs should have independent rate limit buckets
	rdb, _ := newTestRedis(t)
	ctx := context.Background()

	limit := 3
	window := time.Minute

	// Exhaust ip1
	for i := 0; i < limit; i++ {
		check(ctx, rdb, "192.168.1.1", limit, window, time.Now())
	}

	// ip1 should be blocked
	allowed, _, _, err := check(ctx, rdb, "192.168.1.1", limit, window, time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if allowed {
		t.Error("ip1 should be blocked after exhausting limit")
	}

	// ip2 should still be allowed
	allowed, remaining, _, err := check(ctx, rdb, "192.168.1.2", limit, window, time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !allowed {
		t.Error("ip2 should be allowed; independent bucket from ip1")
	}
	if remaining != limit-1 {
		t.Errorf("ip2 remaining = %v, want %v", remaining, limit-1)
	}
}
