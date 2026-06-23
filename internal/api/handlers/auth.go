package handlers

import (
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"time"

	"github.com/BennerG/auth-log-analyzer/internal/auth"
)

// AuthHandler handles token issuance
type AuthHandler struct {
	privateKey    *rsa.PrivateKey
	adminUsername string
	adminPassword string
	expiry        time.Duration
}

func NewAuthHandler(privateKey *rsa.PrivateKey, adminUsername, adminPassword string, expiry time.Duration) *AuthHandler {
	return &AuthHandler{
		privateKey:    privateKey,
		adminUsername: adminUsername,
		adminPassword: adminPassword,
		expiry:        expiry,
	}
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Login validates credentials and issues a signed RS256 JWT
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Password == "" {
		http.Error(w, `{"error":"username and password are required"}`, http.StatusBadRequest)
		return
	}

	// Constant-time comparison to prevent timing attacks.
	// A timing attack lets an attacker infer how many characters of their
	// guess matched by measuring how long the comparison took. crypto/sublte.ConstantTimeCompare
	// always takes the same amount of time regardless of where the strings diverge.
	if !constantTimeEqual(req.Username, h.adminUsername) || !constantTimeEqual(req.Password, h.adminPassword) {
		http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
		return
	}

	token, expiresAt, err := auth.IssueToken(h.privateKey, req.Username, "admin", h.expiry)
	if err != nil {
		http.Error(w, `{"error":"failed to issue token"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(loginResponse{
		Token:     token,
		ExpiresAt: expiresAt,
	})
}

// constantTimeEqual wraps the crypto/subtle.ConstantTimeCompare for string comparison.
func constantTimeEqual(a, b string) bool {
	// lengths must match first
	if len(a) != len(b) {
		return false
	}

	// XOR lengths to keep timing consistent
	var result byte
	for i := range a {
		result |= a[i] ^ b[i]
	}
	return result == 0
}
