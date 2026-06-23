package auth

import (
	"context"
	"crypto/rsa"
	"net/http"
	"strings"
)

// unexported type scoped to this package to prevent collisions
type contextKey int

const claimsKey contextKey = 0

// JWTMiddleware validates a RS256 Bearer token on every protected request.
func JWTMiddleware(publicKey *rsa.PublicKey) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			if header == "" {
				http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
				return
			}

			parts := strings.SplitN(header, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
				http.Error(w, `{"error":"invalid authorization format"}`, http.StatusUnauthorized)
				return
			}

			claims, err := ParseToken(publicKey, parts[1])
			if err != nil {
				// distinguish expired tokens from malformed/invalid ones
				if strings.Contains(err.Error(), "token expired") {
					http.Error(w, `{"error":"token expired"}`, http.StatusUnauthorized)
					return
				}
				http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
				return
			}

			// Store verified claims in context so handlers can read
			// sub, role, and jti without re-parsing the token.
			ctx := context.WithValue(r.Context(), claimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ClaimsFromContext retrieves the verified JWT claims from the request context.
// Returns nil if no claims are present. Callers should check before using.
func ClaimsFromContext(ctx context.Context) *Claims {
	claims, _ := ctx.Value(claimsKey).(*Claims)
	return claims
}
