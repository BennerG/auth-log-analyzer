package handlers

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/BennerG/auth-log-analyzer/internal/auth"
)

var testPrivateKey *rsa.PrivateKey

func TestMain(m *testing.M) {
	var err error
	testPrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("failed to generate test RSA key: " + err.Error())
	}
	m.Run()
}

func newTestAuthHandler() *AuthHandler {
	return NewAuthHandler(testPrivateKey, "admin", "test-password", 15*time.Minute)
}

func TestLogin(t *testing.T) {
	tests := []struct {
		name       string
		body       any
		wantStatus int
		wantToken  bool
		wantBody   string
	}{
		{
			name:       "valid credentials return 200 with token",
			body:       map[string]string{"username": "admin", "password": "test-password"},
			wantStatus: http.StatusOK,
			wantToken:  true,
		},
		{
			name:       "wrong password returns 401",
			body:       map[string]string{"username": "admin", "password": "wrongpassword"},
			wantStatus: http.StatusUnauthorized,
			wantBody:   "invalid credentials",
		},
		{
			name:       "wrong username returns 401",
			body:       map[string]string{"username": "notadmin", "password": "test-password"},
			wantStatus: http.StatusUnauthorized,
			wantBody:   "invalid credentials",
		},
		{
			name:       "missing password returns 400",
			body:       map[string]string{"username": "admin"},
			wantStatus: http.StatusBadRequest,
			wantBody:   "username and password are required",
		},
		{
			name:       "missing username returns 400",
			body:       map[string]string{"password": "test-password"},
			wantStatus: http.StatusBadRequest,
			wantBody:   "username and password are required",
		},
		{
			name:       "empty body returns 400",
			body:       map[string]string{},
			wantStatus: http.StatusBadRequest,
			wantBody:   "username and password are required",
		},
		{
			name:       "malformed JSON returns 400",
			body:       "not-json",
			wantStatus: http.StatusBadRequest,
			wantBody:   "invalid request body",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := newTestAuthHandler()

			var bodyBytes []byte
			var err error

			// Handle malformed JSON case separately
			if s, ok := tt.body.(string); ok {
				bodyBytes = []byte(s)
			} else {
				bodyBytes, err = json.Marshal(tt.body)
				if err != nil {
					t.Fatalf("failed to marshal request body: %v", err)
				}
			}

			req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(bodyBytes))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			handler.Login(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %v, want %v", w.Code, tt.wantStatus)
			}

			if tt.wantBody != "" && !containsString(w.Body.String(), tt.wantBody) {
				t.Errorf("body = %v, want it to contain %q", w.Body.String(), tt.wantBody)
			}

			if tt.wantToken {
				var resp map[string]any
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response body: %v", err)
				}

				token, ok := resp["token"].(string)
				if !ok || token == "" {
					t.Error("expected non-empty token in response")
				}

				expiresAt, ok := resp["expires_at"].(string)
				if !ok || expiresAt == "" {
					t.Error("expected non-empty expires_at in response")
				}

				// Verify the token is actually parseable and carries correct claims
				publicKey := &testPrivateKey.PublicKey
				claims, err := auth.ParseToken(publicKey, token)
				if err != nil {
					t.Fatalf("issued token failed to parse: %v", err)
				}
				if claims.Subject != "admin" {
					t.Errorf("Subject = %v, want admin", claims.Subject)
				}
				if claims.Role != "admin" {
					t.Errorf("Role = %v, want admin", claims.Role)
				}
				if claims.ID == "" {
					t.Error("expected non-empty jti claim")
				}
			}
		})
	}
}

func TestLoginTimingAttack(t *testing.T) {
	// Verify that wrong username and wrong password return the same generic error.
	// This is a behavioral check, not a timing measurement.
	handler := newTestAuthHandler()

	wrongUser := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewBufferString(`{"username":"wronguser","password":"test-password"}`))
	req.Header.Set("Content-Type", "application/json")
	handler.Login(wrongUser, req)

	wrongPass := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewBufferString(`{"username":"admin","password":"wrongpassword"}`))
	req.Header.Set("Content-Type", "application/json")
	handler.Login(wrongPass, req)

	if wrongUser.Code != wrongPass.Code {
		t.Errorf("wrong username status %v != wrong password status %v; leaks username existence", wrongUser.Code, wrongPass.Code)
	}
	if wrongUser.Body.String() != wrongPass.Body.String() {
		t.Errorf("wrong username body %q != wrong password body %q; leaks username existence", wrongUser.Body.String(), wrongPass.Body.String())
	}
}

func containsString(s, substr string) bool {
	for i := range s {
		if i+len(substr) <= len(s) && s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
