package service_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/BennerG/auth-log-analyzer/internal/db"
	"github.com/BennerG/auth-log-analyzer/internal/models"
	"github.com/BennerG/auth-log-analyzer/internal/service"
	"github.com/jackc/pgx/v5/pgxpool"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	ctx := context.Background()

	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://postgres:postgres@localhost:5432/auth_log_analyzer?sslmode=disable"
	}

	var err error
	testPool, err = db.NewPool(ctx, dsn)
	if err != nil {
		fmt.Printf("failed to connect to test database: %v\n", err)
		fmt.Println("hint: is docker-compose up running?")
		os.Exit(1)
	}
	defer testPool.Close()

	// Clean slate before each test run
	_, err = testPool.Exec(ctx, `TRUNCATE TABLE auth_events RESTART IDENTITY CASCADE`)
	if err != nil {
		fmt.Printf("failed to truncate test data: %v\n", err)
		os.Exit(1)
	}

	os.Exit(m.Run())
}

func TestCreateEvent(t *testing.T) {
	svc := service.NewEventService(testPool)
	ctx := context.Background()

	req := models.CreateEventRequest{
		UserID:    "user-123",
		IPAddress: "192.168.1.1",
		EventType: models.EventTypeFailedLogin,
		Status:    models.StatusFailure,
		UserAgent: "Mozilla/5.0",
	}

	event, err := svc.CreateEvent(ctx, req)
	if err != nil {
		t.Fatalf("CreateEvent failed: %v", err)
	}

	if event.ID == 0 {
		t.Error("expected non-zero ID")
	}
	if event.UserID != req.UserID {
		t.Errorf("expected user_id %q, got %q", req.UserID, event.UserID)
	}
	if event.IPAddress != req.IPAddress {
		t.Errorf("expected ip_address %q, got %q", req.IPAddress, event.IPAddress)
	}
	if event.EventType != req.EventType {
		t.Errorf("expected event_type %q, got %q", req.EventType, event.EventType)
	}
	if event.CreatedAt.IsZero() {
		t.Error("expected non-zero created_at")
	}
}

func TestListEvents(t *testing.T) {
	svc := service.NewEventService(testPool)
	ctx := context.Background()

	// Seed two events for different users
	for _, userID := range []string{"user-list-a", "user-list-b"} {
		_, err := svc.CreateEvent(ctx, models.CreateEventRequest{
			UserID:    userID,
			IPAddress: "10.0.0.1",
			EventType: models.EventTypeLogin,
			Status:    models.StatusSuccess,
		})
		if err != nil {
			t.Fatalf("seeding event for %s: %v", userID, err)
		}
	}

	t.Run("list all events", func(t *testing.T) {
		events, err := svc.ListEvents(ctx, "", 50)
		if err != nil {
			t.Fatalf("ListEvents failed: %v", err)
		}
		if len(events) < 2 {
			t.Errorf("expected at least 2 events, got %d", len(events))
		}
	})

	t.Run("filter by user_id", func(t *testing.T) {
		events, err := svc.ListEvents(ctx, "user-list-a", 50)
		if err != nil {
			t.Fatalf("ListEvents failed: %v", err)
		}
		for _, e := range events {
			if e.UserID != "user-list-a" {
				t.Errorf("expected user_id %q, got %q", "user-list-a", e.UserID)
			}
		}
	})

	t.Run("limit clamped to 100", func(t *testing.T) {
		events, err := svc.ListEvents(ctx, "", 999)
		if err != nil {
			t.Fatalf("ListEvents failed: %v", err)
		}
		if len(events) > 100 {
			t.Errorf("expected at most 100 events, got %d", len(events))
		}
	})
}

func TestGetSuspiciousIPs(t *testing.T) {
	svc := service.NewEventService(testPool)
	ctx := context.Background()

	// Seed 6 failed logins from the same IP
	for i := 0; i < 6; i++ {
		_, err := svc.CreateEvent(ctx, models.CreateEventRequest{
			UserID:    fmt.Sprintf("victim-%d", i),
			IPAddress: "172.16.0.99",
			EventType: models.EventTypeFailedLogin,
			Status:    models.StatusFailure,
		})
		if err != nil {
			t.Fatalf("seeding failed login: %v", err)
		}
	}

	ips, err := svc.GetSuspiciousIPs(ctx, 5, 1*time.Hour)
	if err != nil {
		t.Fatalf("GetSuspiciousIPs failed: %v", err)
	}

	found := false
	for _, ip := range ips {
		if ip.IPAddress == "172.16.0.99" {
			found = true
			if ip.FailedCount < 6 {
				t.Errorf("expected at least 6 failed attempts, got %d", ip.FailedCount)
			}
			if ip.UniqueUsers < 6 {
				t.Errorf("expected at least 6 unique users, got %d", ip.UniqueUsers)
			}
		}
	}

	if !found {
		t.Error("expected 172.16.0.99 in suspicious IPs, not found")
	}
}

func TestGetUserActivity(t *testing.T) {
	svc := service.NewEventService(testPool)
	ctx := context.Background()

	// Seed mixed success/failure events for a known user
	for i, status := range []models.EventStatus{
		models.StatusSuccess,
		models.StatusFailure,
		models.StatusFailure,
	} {
		_, err := svc.CreateEvent(ctx, models.CreateEventRequest{
			UserID:    "user-activity-test",
			IPAddress: fmt.Sprintf("10.1.1.%d", i+1),
			EventType: models.EventTypeLogin,
			Status:    status,
		})
		if err != nil {
			t.Fatalf("seeding activity event: %v", err)
		}
	}

	activity, err := svc.GetUserActivity(ctx, 1*time.Hour)
	if err != nil {
		t.Fatalf("GetUserActivity failed: %v", err)
	}

	found := false
	for _, u := range activity {
		if u.UserID == "user-activity-test" {
			found = true
			if u.EventCount < 3 {
				t.Errorf("expected at least 3 events, got %d", u.EventCount)
			}
			if u.FailedCount < 2 {
				t.Errorf("expected at least 2 failures, got %d", u.FailedCount)
			}
			if u.UniqueIPs < 3 {
				t.Errorf("expected at least 3 unique IPs, got %d", u.UniqueIPs)
			}
		}
	}

	if !found {
		t.Error("expected user-activity-test in activity results, not found")
	}
}
