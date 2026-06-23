package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"
)

// package-level key pair shared across all tests in this package
var (
	testPrivateKey *rsa.PrivateKey
	testPublicKey  *rsa.PublicKey
)

func TestMain(m *testing.M) {
	var err error
	testPrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("failed to generate test RSA key: " + err.Error())
	}
	testPublicKey = &testPrivateKey.PublicKey
	m.Run()
}

func TestIssueToken(t *testing.T) {
	tests := []struct {
		name    string
		subject string
		role    string
		expiry  time.Duration
		wantErr bool
	}{
		{
			name:    "issues valid token",
			subject: "admin",
			role:    "admin",
			expiry:  15 * time.Minute,
			wantErr: false,
		},
		{
			name:    "issues token with custom role",
			subject: "user-123",
			role:    "viewer",
			expiry:  time.Hour,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, expiresAt, err := IssueToken(testPrivateKey, tt.subject, tt.role, tt.expiry)
			if (err != nil) != tt.wantErr {
				t.Fatalf("IssueToken() error = %v, wantErr %v", err, tt.wantErr)
			}
			if token == "" {
				t.Error("expected non-empty token string")
			}
			if expiresAt.Before(time.Now()) {
				t.Error("expiresAt should be in the future")
			}
		})
	}
}

func TestParseToken(t *testing.T) {
	// Generate a second key pair to test signature rejection
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate second RSA key: %v", err)
	}

	validToken, _, err := IssueToken(testPrivateKey, "admin", "admin", 15*time.Minute)
	if err != nil {
		t.Fatalf("failed to issue valid token for tests: %v", err)
	}

	expiredToken, _, err := IssueToken(testPrivateKey, "admin", "admin", -1*time.Minute)
	if err != nil {
		t.Fatalf("failed to issue expired token for tests: %v", err)
	}

	wrongKeyToken, _, err := IssueToken(otherKey, "admin", "admin", 15*time.Minute)
	if err != nil {
		t.Fatalf("failed to issue wrong-key token for tests: %v", err)
	}

	tests := []struct {
		name        string
		token       string
		wantErr     bool
		wantExpired bool
		wantSub     string
		wantRole    string
	}{
		{
			name:     "valid token parses correctly",
			token:    validToken,
			wantErr:  false,
			wantSub:  "admin",
			wantRole: "admin",
		},
		{
			name:        "expired token returns error",
			token:       expiredToken,
			wantErr:     true,
			wantExpired: true,
		},
		{
			name:    "token signed with wrong key is rejected",
			token:   wrongKeyToken,
			wantErr: true,
		},
		{
			name:    "malformed token string is rejected",
			token:   "this.is.notavalidjwt",
			wantErr: true,
		},
		{
			name:    "empty token string is rejected",
			token:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims, err := ParseToken(testPublicKey, tt.token)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseToken() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantExpired && err != nil {
				if !strings.Contains(err.Error(), "token expired") {
					t.Errorf("expected 'token expired' in error, got: %v", err)
				}
			}
			if !tt.wantErr {
				if claims.Subject != tt.wantSub {
					t.Errorf("Subject = %v, want %v", claims.Subject, tt.wantSub)
				}
				if claims.Role != tt.wantRole {
					t.Errorf("Role = %v, want %v", claims.Role, tt.wantRole)
				}
				if claims.ID == "" {
					t.Error("expected non-empty jti claim")
				}
			}
		})
	}
}

func TestClaimsRoundTrip(t *testing.T) {
	// Verify all claims survive the sign/parse round trip intact
	token, _, err := IssueToken(testPrivateKey, "user-456", "viewer", 30*time.Minute)
	if err != nil {
		t.Fatalf("IssueToken() error: %v", err)
	}

	claims, err := ParseToken(testPublicKey, token)
	if err != nil {
		t.Fatalf("ParseToken() error: %v", err)
	}

	if claims.Subject != "user-456" {
		t.Errorf("Subject = %v, want user-456", claims.Subject)
	}
	if claims.Role != "viewer" {
		t.Errorf("Role = %v, want viewer", claims.Role)
	}
	if claims.ID == "" {
		t.Error("jti should be non-empty")
	}
	if claims.ExpiresAt == nil {
		t.Error("exp claim should be set")
	}
	if claims.IssuedAt == nil {
		t.Error("iat claim should be set")
	}
}
