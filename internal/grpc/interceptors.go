package grpc

import (
	"context"
	"time"

	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// UnaryLoggingInterceptor logs method, peer IP, duration, and status code for
// every unary RPC.
func UnaryLoggingInterceptor(logger zerolog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		start := time.Now()

		ip := peerIP(ctx)

		resp, err := handler(ctx, req)

		code := codes.OK
		if err != nil {
			code = status.Code(err)
		}

		event := logger.Info()
		if err != nil {
			event = logger.Error().Err(err)
		}

		event.
			Str("method", info.FullMethod).
			Str("peer_ip", ip).
			Str("code", code.String()).
			Dur("duration", time.Since(start)).
			Msg("gRPC unary request")

		return resp, err
	}
}

// StreamLoggingInterceptor logs method, peer IP, duration, and status code for
// every streaming RPC.
func StreamLoggingInterceptor(logger zerolog.Logger) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		start := time.Now()

		ip := peerIP(ss.Context())

		err := handler(srv, ss)

		code := codes.OK
		if err != nil {
			code = status.Code(err)
		}

		event := logger.Info()
		if err != nil {
			event = logger.Error().Err(err)
		}

		event.
			Str("method", info.FullMethod).
			Str("peer_ip", ip).
			Str("code", code.String()).
			Dur("duration", time.Since(start)).
			Bool("server_stream", info.IsServerStream).
			Msg("gRPC stream request")

		return err
	}
}

// peerIP extracts the client IP from the gRPC peer context.
// Returns "unknown" if the peer is not available.
func peerIP(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "unknown"
	}
	return p.Addr.String()
}
