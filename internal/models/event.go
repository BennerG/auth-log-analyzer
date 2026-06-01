package models

import (
	"time"
)

type EventType string
type EventStatus string

const (
	EventTypeLogin          EventType = "login"
	EventTypeLogout         EventType = "logout"
	EventTypeTokenIssued    EventType = "token_issued"
	EventTypeTokenRefresh   EventType = "token_refresh"
	EventTypeTokenRevoked   EventType = "token_revoked"
	EventTypePasswordChange EventType = "password_change"
	EventTypeFailedLogin    EventType = "failed_login"
)

const (
	StatusSuccess EventStatus = "success"
	StatusFailure EventStatus = "failure"
	StatusBlocked EventStatus = "blocked"
)

type AuthEvent struct {
	ID        int64       `db:"id"         json:"id"`
	UserID    string      `db:"user_id"    json:"user_id"`
	IPAddress string      `db:"ip_address" json:"ip_address"`
	EventType EventType   `db:"event_type" json:"event_type"`
	Status    EventStatus `db:"status"     json:"status"`
	UserAgent string      `db:"user_agent" json:"user_agent,omitempty"`
	Metadata  []byte      `db:"metadata"   json:"metadata,omitempty"` // JSONB — flexible extra fields
	CreatedAt time.Time   `db:"created_at" json:"created_at"`
}

// Used for POST /events request body
type CreateEventRequest struct {
	UserID    string      `json:"user_id"`
	IPAddress string      `json:"ip_address"`
	EventType EventType   `json:"event_type"`
	Status    EventStatus `json:"status"`
	UserAgent string      `json:"user_agent,omitempty"`
	Metadata  []byte      `json:"metadata,omitempty"`
}

// Used for analysis endpoints
type SuspiciousIP struct {
	IPAddress   string    `db:"ip_address"   json:"ip_address"`
	FailedCount int       `db:"failed_count" json:"failed_count"`
	UniqueUsers int       `db:"unique_users" json:"unique_users"`
	LastSeen    time.Time `db:"last_seen" json:"last_seen"`
}

type UserActivity struct {
	UserID      string    `db:"user_id"     json:"user_id"`
	EventCount  int       `db:"event_count" json:"event_count"`
	FailedCount int       `db:"failed_count" json:"failed_count"`
	LastSeen    time.Time `db:"last_seen"   json:"last_seen"`
	UniqueIPs   int       `db:"unique_ips"  json:"unique_ips"`
}
