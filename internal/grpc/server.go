package grpc

import (
	"context"
	"fmt"
	"time"

	authlogv1 "github.com/BennerG/auth-log-analyzer/gen/authlog/v1"
	"github.com/BennerG/auth-log-analyzer/internal/models"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	googlegrpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Server implements AuthLogServiceServer.
type Server struct {
	authlogv1.UnimplementedAuthLogServiceServer
	db     *pgxpool.Pool
	logger zerolog.Logger
}

// NewServer constructs a gRPC server with the shared DB pool and logger.
func NewServer(db *pgxpool.Pool, logger zerolog.Logger) *Server {
	return &Server{db: db, logger: logger}
}

// IngestEvent records a single authentication event.
// Mirrors the logic in the REST POST /events handler.
func (s *Server) IngestEvent(ctx context.Context, req *authlogv1.IngestEventRequest) (*authlogv1.IngestEventResponse, error) {
	if req.GetUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}
	if req.GetIpAddress() == "" {
		return nil, status.Error(codes.InvalidArgument, "ip_address is required")
	}
	if req.GetEventType() == "" {
		return nil, status.Error(codes.InvalidArgument, "event_type is required")
	}

	// Derive status from event_type so the DB constraint is satisfied.
	eventStatus := models.StatusSuccess
	if req.GetEventType() == "failed_login" {
		eventStatus = models.StatusFailure
	}

	var eventID int64
	err := s.db.QueryRow(ctx,
		`INSERT INTO auth_events (user_id, ip_address, event_type, status)
		 VALUES ($1, $2::inet, $3, $4)
		 RETURNING id`,
		req.GetUserId(),
		req.GetIpAddress(),
		req.GetEventType(),
		string(eventStatus),
	).Scan(&eventID)
	if err != nil {
		s.logger.Error().Err(err).Msg("grpc: failed to insert auth event")
		return nil, status.Error(codes.Internal, "failed to record event")
	}

	return &authlogv1.IngestEventResponse{
		EventId: fmt.Sprintf("%d", eventID),
		Message: "event recorded",
	}, nil
}

// StreamSuspiciousIPs streams suspicious IP results to the client one row at a time.
// Uses the same query as the REST GET /analysis/suspicious-ips handler.
// The stream closes naturally when all rows have been sent.
func (s *Server) StreamSuspiciousIPs(req *authlogv1.StreamSuspiciousIPsRequest, stream googlegrpc.ServerStreamingServer[authlogv1.StreamSuspiciousIPsResponse]) error {
	threshold := int(req.GetMinFailures())
	if threshold <= 0 {
		threshold = 5
	}

	since := 24 * time.Hour

	rows, err := s.db.Query(stream.Context(),
		`SELECT
			host(ip_address),
			COUNT(*)                AS failed_count,
			COUNT(DISTINCT user_id) AS unique_users,
			MAX(created_at)         AS last_seen
		 FROM auth_events
		 WHERE status = 'failure'
		   AND event_type = 'failed_login'
		   AND created_at >= NOW() - $1::INTERVAL
		 GROUP BY ip_address
		 HAVING COUNT(*) >= $2
		 ORDER BY failed_count DESC`,
		since.String(),
		threshold,
	)
	if err != nil {
		s.logger.Error().Err(err).Msg("grpc: failed to query suspicious IPs")
		return status.Error(codes.Internal, "failed to query suspicious IPs")
	}
	defer rows.Close()

	for rows.Next() {
		var ip models.SuspiciousIP
		if err := rows.Scan(&ip.IPAddress, &ip.FailedCount, &ip.UniqueUsers, &ip.LastSeen); err != nil {
			s.logger.Error().Err(err).Msg("grpc: failed to scan suspicious IP row")
			return status.Error(codes.Internal, "failed to read results")
		}

		if err := stream.Send(&authlogv1.StreamSuspiciousIPsResponse{
			IpAddress:    ip.IPAddress,
			FailureCount: int32(ip.FailedCount),
			UniqueUsers:  int32(ip.UniqueUsers),
			LastSeen:     ip.LastSeen.Format(time.RFC3339),
		}); err != nil {
			// Client disconnected mid-stream -- not an application error.
			return err
		}
	}

	if err := rows.Err(); err != nil {
		s.logger.Error().Err(err).Msg("grpc: row iteration error")
		return status.Error(codes.Internal, "error reading results")
	}

	return nil
}
