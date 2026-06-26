package auth

import (
	"context"
	"crypto/rsa"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// UnaryJWTInterceptor validates a RS256 Bearer token for every unary RPC.
func UnaryJWTInterceptor(publicKey *rsa.PublicKey) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		claims, err := claimsFromMetadata(ctx, publicKey)
		if err != nil {
			return nil, err
		}

		ctx = context.WithValue(ctx, claimsKey, claims)
		return handler(ctx, req)
	}
}

// StreamJWTInterceptor validates a RS256 Bearer token for every streaming RPC.
func StreamJWTInterceptor(publicKey *rsa.PublicKey) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		claims, err := claimsFromMetadata(ss.Context(), publicKey)
		if err != nil {
			return err
		}

		ctx := context.WithValue(ss.Context(), claimsKey, claims)
		return handler(srv, &wrappedStream{ServerStream: ss, ctx: ctx})
	}
}

// claimsFromMetadata extracts and validates the Bearer token from gRPC metadata.
func claimsFromMetadata(ctx context.Context, publicKey *rsa.PublicKey) (*Claims, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing metadata")
	}

	values := md.Get("authorization")
	if len(values) == 0 {
		return nil, status.Error(codes.Unauthenticated, "missing authorization header")
	}

	parts := strings.SplitN(values[0], " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return nil, status.Error(codes.Unauthenticated, "invalid authorization format")
	}

	claims, err := ParseToken(publicKey, parts[1])
	if err != nil {
		if strings.Contains(err.Error(), "token expired") {
			return nil, status.Error(codes.Unauthenticated, "token expired")
		}
		return nil, status.Error(codes.Unauthenticated, "invalid token")
	}

	return claims, nil
}

// wrappedStream replaces the context on a grpc.ServerStream.
type wrappedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedStream) Context() context.Context {
	return w.ctx
}
