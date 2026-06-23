package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// nextHandler is a simple handler that records whether it was called.
// Used to verify the middleware either passes through or blocks correctly.
func nextHandler(called *bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*called = true
		w.WriteHeader(http.StatusOK)
	})
}

func TestJWTMiddleware(t *testing.T) {
	validToken, _, err := IssueToken(testPrivateKey, "admin", "admin", 15*time.Minute)
	if err != nil {
		t.Fatalf("failed to issue valid token for tests: %v", err)
	}

	expiredToken, _, err := IssueToken(testPrivateKey, "admin", "admin", -1*time.Minute)
	if err != nil {
		t.Fatalf("failed to issue expired token for tests: %v", err)
	}

	tests := []struct {
		name           string
		authHeader     string
		wantStatus     int
		wantNextCalled bool
		wantBody       string
	}{
		{
			name:           "valid token passes through",
			authHeader:     "Bearer " + validToken,
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
		},
		{
			name:           "missing authorization header returns 401",
			authHeader:     "",
			wantStatus:     http.StatusUnauthorized,
			wantNextCalled: false,
			wantBody:       "missing authorization header",
		},
		{
			name:           "malformed header returns 401",
			authHeader:     "Token " + validToken,
			wantStatus:     http.StatusUnauthorized,
			wantNextCalled: false,
			wantBody:       "invalid authorization format",
		},
		{
			name:           "invalid token returns 401",
			authHeader:     "Bearer thisisnotavalidtoken",
			wantStatus:     http.StatusUnauthorized,
			wantNextCalled: false,
			wantBody:       "invalid token",
		},
		{
			name:           "expired token returns 401 with expired message",
			authHeader:     "Bearer " + expiredToken,
			wantStatus:     http.StatusUnauthorized,
			wantNextCalled: false,
			wantBody:       "token expired",
		},
		{
			name:           "bearer prefix is case insensitive",
			authHeader:     "bearer " + validToken,
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			handler := JWTMiddleware(testPublicKey)(nextHandler(&called))

			req := httptest.NewRequest(http.MethodGet, "/events", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %v, want %v", w.Code, tt.wantStatus)
			}
			if called != tt.wantNextCalled {
				t.Errorf("next called = %v, want %v", called, tt.wantNextCalled)
			}
			if tt.wantBody != "" && !strings.Contains(w.Body.String(), tt.wantBody) {
				t.Errorf("body = %v, want it to contain %v", w.Body.String(), tt.wantBody)
			}
		})
	}
}

func TestJWTMiddlewareStoresClaimsInContext(t *testing.T) {
	validToken, _, err := IssueToken(testPrivateKey, "user-789", "admin", 15*time.Minute)
	if err != nil {
		t.Fatalf("failed to issue token: %v", err)
	}

	var capturedClaims *Claims
	capturingHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedClaims = ClaimsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	handler := JWTMiddleware(testPublicKey)(capturingHandler)

	req := httptest.NewRequest(http.MethodGet, "/events", nil)
	req.Header.Set("Authorization", "Bearer "+validToken)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if capturedClaims == nil {
		t.Fatal("expected claims in context, got nil")
	}
	if capturedClaims.Subject != "user-789" {
		t.Errorf("Subject = %v, want user-789", capturedClaims.Subject)
	}
	if capturedClaims.Role != "admin" {
		t.Errorf("Role = %v, want admin", capturedClaims.Role)
	}
}

func TestClaimsFromContext(t *testing.T) {
	t.Run("returns nil when no claims in context", func(t *testing.T) {
		ctx := context.Background()
		claims := ClaimsFromContext(ctx)
		if claims != nil {
			t.Errorf("expected nil claims, got %v", claims)
		}
	})

	t.Run("returns claims when present in context", func(t *testing.T) {
		expected := &Claims{Role: "admin"}
		ctx := context.WithValue(context.Background(), claimsKey, expected)
		claims := ClaimsFromContext(ctx)
		if claims != expected {
			t.Errorf("expected %v, got %v", expected, claims)
		}
	})
}
