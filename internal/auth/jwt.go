package auth

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Claims represents the JWT payload. RegisteredClaims covers sub, exp, iat, jti.
// Role is a custom claim for future RBAC extensibility.
type Claims struct {
	jwt.RegisteredClaims
	Role string `json:"role"`
}

// IssueToken signs a new RS256 JWT for the given subject and role.
func IssueToken(privateKey *rsa.PrivateKey, subject, role string, expiry time.Duration) (string, time.Time, error) {
	now := time.Now()
	expiresAt := now.Add(expiry)

	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   subject,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			// jti placeholder for future revocation store
			ID: uuid.NewString(),
		},
		Role: role,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	signed, err := token.SignedString(privateKey)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("auth: sign token: %w", err)
	}

	return signed, expiresAt, nil
}

// ParseToken verifies the RS256 signature and returns the claims.
// Returns an error if the token is expired, malformed, or has an invalid signature.
func ParseToken(publicKey *rsa.PublicKey, tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (any, error) {
		// only accept tokens signed with RS256
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("auth: unexpected signing method: %v", t.Header["alg"])
		}
		return publicKey, nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, fmt.Errorf("auth: token expired: %w", err)
		}
		return nil, fmt.Errorf("auth: parse token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("auth: invalid token claims")
	}

	return claims, nil
}

// LoadPrivateKey reads and parses an RSA private key from a PEM file.
func LoadPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("auth: read private key: %w", err)
	}

	key, err := jwt.ParseRSAPrivateKeyFromPEM(data)
	if err != nil {
		return nil, fmt.Errorf("auth: parse private key: %w", err)
	}

	return key, nil
}

// LoadPublicKey reads and parses an RSA public key from a PEM file.
func LoadPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("auth: read public key: %w", err)
	}

	key, err := jwt.ParseRSAPublicKeyFromPEM(data)
	if err != nil {
		return nil, fmt.Errorf("auth: parse public key: %w", err)
	}

	return key, nil
}
