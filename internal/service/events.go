package service

import (
	"context"
	"fmt"
	"time"

	"github.com/BennerG/auth-log-analyzer/internal/models"
	"github.com/jackc/pgx/v5/pgxpool"
)

type EventService struct {
	db *pgxpool.Pool
}

func NewEventService(db *pgxpool.Pool) *EventService {
	return &EventService{db: db}
}

// CreateEvent inserts a new auth event into the database
func (s *EventService) CreateEvent(ctx context.Context, req models.CreateEventRequest) (*models.AuthEvent, error) {
	query := `
		INSERT INTO auth_events (user_id, ip_address, event_type, status, user_agent, metadata)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, user_id, ip_address, event_type, status, user_agent, metadata, created_at
	`

	var event models.AuthEvent
	err := s.db.QueryRow(ctx, query,
		req.UserID,
		req.IPAddress,
		req.EventType,
		req.Status,
		req.UserAgent,
		req.Metadata,
	).Scan(
		&event.ID,
		&event.UserID,
		&event.IPAddress,
		&event.EventType,
		&event.Status,
		&event.UserAgent,
		&event.Metadata,
		&event.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("inserting auth event: %w", err)
	}

	return &event, nil
}

// ListEvents returns auth events with optional filters
func (s *EventService) ListEvents(ctx context.Context, userID string, limit int) ([]models.AuthEvent, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}

	query := `
		SELECT id, user_id, ip_address, event_type, status, user_agent, metadata, created_at
		FROM auth_events
		WHERE ($1 = '' OR user_id = $1)
		ORDER BY created_at DESC
		LIMIT $2
	`

	rows, err := s.db.Query(ctx, query, userID, limit)
	if err != nil {
		return nil, fmt.Errorf("querying auth events: %w", err)
	}
	defer rows.Close()

	var events []models.AuthEvent
	for rows.Next() {
		var e models.AuthEvent
		err := rows.Scan(
			&e.ID,
			&e.UserID,
			&e.IPAddress,
			&e.EventType,
			&e.Status,
			&e.UserAgent,
			&e.Metadata,
			&e.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scanning auth event: %w", err)
		}
		events = append(events, e)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating auth events: %w", err)
	}

	return events, nil
}

// GetSuspiciousIPs returns IPs with failed login attempts above a threshold
// within the given time window
func (s *EventService) GetSuspiciousIPs(ctx context.Context, threshold int, since time.Duration) ([]models.SuspiciousIP, error) {
	if threshold <= 0 {
		threshold = 5
	}

	query := `
		SELECT
			ip_address::TEXT,
			COUNT(*)                                    AS failed_count,
			COUNT(DISTINCT user_id)                     AS unique_users,
			MAX(created_at)                             AS last_seen
		FROM auth_events
		WHERE status = 'failure'
		  AND event_type = 'failed_login'
		  AND created_at >= NOW() - $1::INTERVAL
		GROUP BY ip_address
		HAVING COUNT(*) >= $2
		ORDER BY failed_count DESC
	`

	rows, err := s.db.Query(ctx, query, since.String(), threshold)
	if err != nil {
		return nil, fmt.Errorf("querying suspicious IPs: %w", err)
	}
	defer rows.Close()

	var results []models.SuspiciousIP
	for rows.Next() {
		var ip models.SuspiciousIP
		err := rows.Scan(&ip.IPAddress, &ip.FailedCount, &ip.UniqueUsers, &ip.LastSeen)
		if err != nil {
			return nil, fmt.Errorf("scanning suspicious IP: %w", err)
		}
		results = append(results, ip)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating suspicious IPs: %w", err)
	}

	return results, nil
}

// GetUserActivity returns a summary of activity per user
func (s *EventService) GetUserActivity(ctx context.Context, since time.Duration) ([]models.UserActivity, error) {
	query := `
		SELECT
			user_id,
			COUNT(*)                                        AS event_count,
			COUNT(*) FILTER (WHERE status = 'failure')      AS failed_count,
			MAX(created_at)                                 AS last_seen,
			COUNT(DISTINCT ip_address)                      AS unique_ips
		FROM auth_events
		WHERE created_at >= NOW() - $1::INTERVAL
		GROUP BY user_id
		ORDER BY failed_count DESC, event_count DESC
	`

	rows, err := s.db.Query(ctx, query, since.String())
	if err != nil {
		return nil, fmt.Errorf("querying user activity: %w", err)
	}
	defer rows.Close()

	var results []models.UserActivity
	for rows.Next() {
		var u models.UserActivity
		err := rows.Scan(&u.UserID, &u.EventCount, &u.FailedCount, &u.LastSeen, &u.UniqueIPs)
		if err != nil {
			return nil, fmt.Errorf("scanning user activity: %w", err)
		}
		results = append(results, u)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating user activity: %w", err)
	}

	return results, nil
}
