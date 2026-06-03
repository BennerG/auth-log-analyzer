package auth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/BennerG/auth-log-analyzer/internal/auth"
)

func TestAPIKeyMiddleware(t *testing.T) {
	const validKey = "test-api-key"

	// Dummy next handler to confirm request passed through
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := auth.APIKeyMiddleware(validKey)(next)

	tests := []struct {
		name           string
		authHeader     string
		expectedStatus int
	}{
		{
			name:           "valid key",
			authHeader:     "Bearer test-api-key",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "missing header",
			authHeader:     "",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "malformed header — no Bearer prefix",
			authHeader:     "test-api-key",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "wrong key",
			authHeader:     "Bearer wrong-key",
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "Bearer prefix case insensitive",
			authHeader:     "bearer test-api-key",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "empty Bearer value",
			authHeader:     "Bearer ",
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/events", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rr.Code)
			}
		})
	}
}
