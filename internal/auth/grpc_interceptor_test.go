package auth

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// unaryHandler is a simple unary handler that records whether it was called
// and captures the context so tests can inspect stored claims.
func unaryHandler(called *bool, ctx *context.Context) grpc.UnaryHandler {
	return func(c context.Context, req any) (any, error) {
		*called = true
		if ctx != nil {
			*ctx = c
		}
		return nil, nil
	}
}

// streamHandler records whether it was called.
func streamHandler(called *bool) grpc.StreamHandler {
	return func(srv any, stream grpc.ServerStream) error {
		*called = true
		return nil
	}
}

// mockServerStream implements grpc.ServerStream for interceptor testing.
// Only Context() is needed. All other methods are satisfied by the embed.
type mockServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (m *mockServerStream) Context() context.Context { return m.ctx }

// incomingContext builds a context carrying gRPC metadata with the given
// authorization value. Mirrors what grpcurl and real clients send.
func incomingContext(authHeader string) context.Context {
	md := metadata.Pairs("authorization", authHeader)
	return metadata.NewIncomingContext(context.Background(), md)
}

func TestUnaryJWTInterceptor(t *testing.T) {
	validToken, _, err := IssueToken(testPrivateKey, "admin", "admin", 15*time.Minute)
	if err != nil {
		t.Fatalf("failed to issue valid token: %v", err)
	}

	expiredToken, _, err := IssueToken(testPrivateKey, "admin", "admin", -1*time.Minute)
	if err != nil {
		t.Fatalf("failed to issue expired token: %v", err)
	}

	tests := []struct {
		name           string
		ctx            context.Context
		wantCode       codes.Code
		wantNextCalled bool
	}{
		{
			name:           "valid token passes through",
			ctx:            incomingContext("Bearer " + validToken),
			wantCode:       codes.OK,
			wantNextCalled: true,
		},
		{
			name:           "missing metadata returns Unauthenticated",
			ctx:            context.Background(),
			wantCode:       codes.Unauthenticated,
			wantNextCalled: false,
		},
		{
			name:           "missing authorization header returns Unauthenticated",
			ctx:            metadata.NewIncomingContext(context.Background(), metadata.Pairs()),
			wantCode:       codes.Unauthenticated,
			wantNextCalled: false,
		},
		{
			name:           "malformed header returns Unauthenticated",
			ctx:            incomingContext("Token " + validToken),
			wantCode:       codes.Unauthenticated,
			wantNextCalled: false,
		},
		{
			name:           "invalid token returns Unauthenticated",
			ctx:            incomingContext("Bearer notavalidtoken"),
			wantCode:       codes.Unauthenticated,
			wantNextCalled: false,
		},
		{
			name:           "expired token returns Unauthenticated",
			ctx:            incomingContext("Bearer " + expiredToken),
			wantCode:       codes.Unauthenticated,
			wantNextCalled: false,
		},
		{
			name:           "bearer prefix is case insensitive",
			ctx:            incomingContext("bearer " + validToken),
			wantCode:       codes.OK,
			wantNextCalled: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			interceptor := UnaryJWTInterceptor(testPublicKey)
			_, err := interceptor(tt.ctx, nil, &grpc.UnaryServerInfo{}, unaryHandler(&called, nil))

			if tt.wantCode == codes.OK {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if got := status.Code(err); got != tt.wantCode {
					t.Errorf("code = %v, want %v", got, tt.wantCode)
				}
			}

			if called != tt.wantNextCalled {
				t.Errorf("handler called = %v, want %v", called, tt.wantNextCalled)
			}
		})
	}
}

func TestUnaryJWTInterceptorStoresClaimsInContext(t *testing.T) {
	validToken, _, err := IssueToken(testPrivateKey, "user-grpc", "admin", 15*time.Minute)
	if err != nil {
		t.Fatalf("failed to issue token: %v", err)
	}

	var capturedCtx context.Context
	called := false
	interceptor := UnaryJWTInterceptor(testPublicKey)

	_, err = interceptor(
		incomingContext("Bearer "+validToken),
		nil,
		&grpc.UnaryServerInfo{},
		unaryHandler(&called, &capturedCtx),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	claims := ClaimsFromContext(capturedCtx)
	if claims == nil {
		t.Fatal("expected claims in context, got nil")
	}
	if claims.Subject != "user-grpc" {
		t.Errorf("Subject = %v, want user-grpc", claims.Subject)
	}
	if claims.Role != "admin" {
		t.Errorf("Role = %v, want admin", claims.Role)
	}
}

func TestStreamJWTInterceptor(t *testing.T) {
	validToken, _, err := IssueToken(testPrivateKey, "admin", "admin", 15*time.Minute)
	if err != nil {
		t.Fatalf("failed to issue valid token: %v", err)
	}

	expiredToken, _, err := IssueToken(testPrivateKey, "admin", "admin", -1*time.Minute)
	if err != nil {
		t.Fatalf("failed to issue expired token: %v", err)
	}

	tests := []struct {
		name           string
		ctx            context.Context
		wantCode       codes.Code
		wantNextCalled bool
	}{
		{
			name:           "valid token passes through",
			ctx:            incomingContext("Bearer " + validToken),
			wantCode:       codes.OK,
			wantNextCalled: true,
		},
		{
			name:           "missing metadata returns Unauthenticated",
			ctx:            context.Background(),
			wantCode:       codes.Unauthenticated,
			wantNextCalled: false,
		},
		{
			name:           "expired token returns Unauthenticated",
			ctx:            incomingContext("Bearer " + expiredToken),
			wantCode:       codes.Unauthenticated,
			wantNextCalled: false,
		},
		{
			name:           "invalid token returns Unauthenticated",
			ctx:            incomingContext("Bearer notavalidtoken"),
			wantCode:       codes.Unauthenticated,
			wantNextCalled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			interceptor := StreamJWTInterceptor(testPublicKey)
			stream := &mockServerStream{ctx: tt.ctx}

			err := interceptor(nil, stream, &grpc.StreamServerInfo{}, streamHandler(&called))

			if tt.wantCode == codes.OK {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if got := status.Code(err); got != tt.wantCode {
					t.Errorf("code = %v, want %v", got, tt.wantCode)
				}
			}

			if called != tt.wantNextCalled {
				t.Errorf("handler called = %v, want %v", called, tt.wantNextCalled)
			}
		})
	}
}

func TestStreamJWTInterceptorStoresClaimsInContext(t *testing.T) {
	validToken, _, err := IssueToken(testPrivateKey, "user-stream", "viewer", 15*time.Minute)
	if err != nil {
		t.Fatalf("failed to issue token: %v", err)
	}

	var capturedCtx context.Context
	interceptor := StreamJWTInterceptor(testPublicKey)
	stream := &mockServerStream{ctx: incomingContext("Bearer " + validToken)}

	err = interceptor(nil, stream, &grpc.StreamServerInfo{}, func(srv any, ss grpc.ServerStream) error {
		capturedCtx = ss.Context()
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	claims := ClaimsFromContext(capturedCtx)
	if claims == nil {
		t.Fatal("expected claims in context, got nil")
	}
	if claims.Subject != "user-stream" {
		t.Errorf("Subject = %v, want user-stream", claims.Subject)
	}
	if claims.Role != "viewer" {
		t.Errorf("Role = %v, want viewer", claims.Role)
	}
}
