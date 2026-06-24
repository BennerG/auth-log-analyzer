package grpc

import (
	"context"
	"os"
	"testing"
	"time"

	authlogv1 "github.com/BennerG/auth-log-analyzer/gen/authlog/v1"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
	googlegrpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var testDB *pgxpool.Pool

func TestMain(m *testing.M) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://postgres:postgres@localhost:5432/auth_log_analyzer_test?sslmode=disable"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var err error
	testDB, err = pgxpool.New(ctx, dsn)
	if err != nil {
		panic("failed to connect to test database: " + err.Error())
	}
	defer testDB.Close()

	if err := testDB.Ping(ctx); err != nil {
		panic("test database unreachable: " + err.Error())
	}

	if err := migrateTestDB(ctx); err != nil {
		panic("failed to migrate test database: " + err.Error())
	}

	code := m.Run()
	os.Exit(code)
}

// migrateTestDB creates the auth_events table if it does not exist.
// Runs on every test invocation so tests are self-contained.
func migrateTestDB(ctx context.Context) error {
	_, err := testDB.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS auth_events (
			id         BIGSERIAL PRIMARY KEY,
			user_id    TEXT        NOT NULL,
			ip_address INET        NOT NULL,
			event_type TEXT        NOT NULL,
			status     TEXT        NOT NULL,
			user_agent TEXT,
			metadata   JSONB,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`)
	return err
}

// cleanEvents truncates auth_events between tests so each test starts clean.
func cleanEvents(t *testing.T) {
	t.Helper()
	_, err := testDB.Exec(context.Background(), "TRUNCATE TABLE auth_events RESTART IDENTITY")
	if err != nil {
		t.Fatalf("failed to truncate auth_events: %v", err)
	}
}

// newTestServer returns a Server wired to the test DB with a no-op logger.
func newTestServer() *Server {
	return NewServer(testDB, zerolog.Nop())
}

// --- IngestEvent tests ---

func TestIngestEvent(t *testing.T) {
	tests := []struct {
		name     string
		req      *authlogv1.IngestEventRequest
		wantCode codes.Code
		wantID   bool
	}{
		{
			name: "valid failed_login event is recorded",
			req: &authlogv1.IngestEventRequest{
				UserId:    "user-1",
				IpAddress: "10.0.0.1",
				EventType: "failed_login",
			},
			wantCode: codes.OK,
			wantID:   true,
		},
		{
			name: "valid non-failure event defaults to success status",
			req: &authlogv1.IngestEventRequest{
				UserId:    "user-2",
				IpAddress: "10.0.0.2",
				EventType: "login_success",
			},
			wantCode: codes.OK,
			wantID:   true,
		},
		{
			name: "missing user_id returns InvalidArgument",
			req: &authlogv1.IngestEventRequest{
				IpAddress: "10.0.0.3",
				EventType: "failed_login",
			},
			wantCode: codes.InvalidArgument,
		},
		{
			name: "missing ip_address returns InvalidArgument",
			req: &authlogv1.IngestEventRequest{
				UserId:    "user-3",
				EventType: "failed_login",
			},
			wantCode: codes.InvalidArgument,
		},
		{
			name: "missing event_type returns InvalidArgument",
			req: &authlogv1.IngestEventRequest{
				UserId:    "user-4",
				IpAddress: "10.0.0.4",
			},
			wantCode: codes.InvalidArgument,
		},
		{
			name: "invalid ip_address returns Internal from postgres INET cast",
			req: &authlogv1.IngestEventRequest{
				UserId:    "user-5",
				IpAddress: "not-an-ip",
				EventType: "failed_login",
			},
			wantCode: codes.Internal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cleanEvents(t)
			srv := newTestServer()

			resp, err := srv.IngestEvent(context.Background(), tt.req)

			if tt.wantCode == codes.OK {
				if err != nil {
					t.Fatalf("IngestEvent() unexpected error: %v", err)
				}
				if tt.wantID && resp.GetEventId() == "" {
					t.Error("expected non-empty event_id in response")
				}
				if resp.GetMessage() == "" {
					t.Error("expected non-empty message in response")
				}
				return
			}

			if err == nil {
				t.Fatalf("IngestEvent() expected error with code %v, got nil", tt.wantCode)
			}
			if got := status.Code(err); got != tt.wantCode {
				t.Errorf("status code = %v, want %v", got, tt.wantCode)
			}
		})
	}
}

func TestIngestEventStatusDerivation(t *testing.T) {
	cleanEvents(t)
	srv := newTestServer()

	_, err := srv.IngestEvent(context.Background(), &authlogv1.IngestEventRequest{
		UserId:    "user-status-test",
		IpAddress: "10.0.0.99",
		EventType: "failed_login",
	})
	if err != nil {
		t.Fatalf("IngestEvent() error: %v", err)
	}

	var dbStatus string
	err = testDB.QueryRow(context.Background(),
		`SELECT status FROM auth_events WHERE user_id = $1`,
		"user-status-test",
	).Scan(&dbStatus)
	if err != nil {
		t.Fatalf("failed to query inserted event: %v", err)
	}
	if dbStatus != "failure" {
		t.Errorf("status = %v, want failure", dbStatus)
	}
}

// --- StreamSuspiciousIPs tests ---

// mockStream implements grpc.ServerStreamingServer[authlogv1.StreamSuspiciousIPsResponse]
// so we can capture Send() calls without a real gRPC connection.
type mockStream struct {
	googlegrpc.ServerStream
	ctx     context.Context
	results []*authlogv1.StreamSuspiciousIPsResponse
}

func newMockStream() *mockStream {
	return &mockStream{ctx: context.Background()}
}

func (m *mockStream) Send(resp *authlogv1.StreamSuspiciousIPsResponse) error {
	m.results = append(m.results, resp)
	return nil
}

func (m *mockStream) Context() context.Context {
	return m.ctx
}

func TestStreamSuspiciousIPs(t *testing.T) {
	cleanEvents(t)
	srv := newTestServer()

	// Seed enough failed_login events on one IP to exceed the default threshold.
	for i := range 6 {
		_, err := srv.IngestEvent(context.Background(), &authlogv1.IngestEventRequest{
			UserId:    "victim-" + string(rune('0'+i)),
			IpAddress: "10.1.1.1",
			EventType: "failed_login",
		})
		if err != nil {
			t.Fatalf("seed IngestEvent() error: %v", err)
		}
	}

	stream := newMockStream()
	err := srv.StreamSuspiciousIPs(&authlogv1.StreamSuspiciousIPsRequest{MinFailures: 5}, stream)
	if err != nil {
		t.Fatalf("StreamSuspiciousIPs() unexpected error: %v", err)
	}

	if len(stream.results) != 1 {
		t.Fatalf("got %d results, want 1", len(stream.results))
	}

	got := stream.results[0]
	if got.GetIpAddress() != "10.1.1.1" {
		t.Errorf("IpAddress = %v, want 10.1.1.1", got.GetIpAddress())
	}
	if got.GetFailureCount() != 6 {
		t.Errorf("FailureCount = %v, want 6", got.GetFailureCount())
	}
	if got.GetUniqueUsers() != 6 {
		t.Errorf("UniqueUsers = %v, want 6", got.GetUniqueUsers())
	}
	if got.GetLastSeen() == "" {
		t.Error("expected non-empty LastSeen")
	}
}

func TestStreamSuspiciousIPsMinFailuresFilter(t *testing.T) {
	cleanEvents(t)
	srv := newTestServer()

	// Seed 3 failures on one IP and 7 on another.
	for i := range 3 {
		_, err := srv.IngestEvent(context.Background(), &authlogv1.IngestEventRequest{
			UserId:    "u" + string(rune('0'+i)),
			IpAddress: "10.2.2.2",
			EventType: "failed_login",
		})
		if err != nil {
			t.Fatalf("seed error: %v", err)
		}
	}
	for i := range 7 {
		_, err := srv.IngestEvent(context.Background(), &authlogv1.IngestEventRequest{
			UserId:    "v" + string(rune('0'+i)),
			IpAddress: "10.3.3.3",
			EventType: "failed_login",
		})
		if err != nil {
			t.Fatalf("seed error: %v", err)
		}
	}

	stream := newMockStream()
	err := srv.StreamSuspiciousIPs(&authlogv1.StreamSuspiciousIPsRequest{MinFailures: 5}, stream)
	if err != nil {
		t.Fatalf("StreamSuspiciousIPs() error: %v", err)
	}

	// Only 10.3.3.3 with 7 failures should appear -- 10.2.2.2 is below threshold.
	if len(stream.results) != 1 {
		t.Fatalf("got %d results, want 1", len(stream.results))
	}
	if stream.results[0].GetIpAddress() != "10.3.3.3" {
		t.Errorf("IpAddress = %v, want 10.3.3.3", stream.results[0].GetIpAddress())
	}
}

func TestStreamSuspiciousIPsEmptyResult(t *testing.T) {
	cleanEvents(t)
	srv := newTestServer()

	stream := newMockStream()
	err := srv.StreamSuspiciousIPs(&authlogv1.StreamSuspiciousIPsRequest{MinFailures: 5}, stream)
	if err != nil {
		t.Fatalf("StreamSuspiciousIPs() unexpected error: %v", err)
	}
	if len(stream.results) != 0 {
		t.Errorf("got %d results, want 0", len(stream.results))
	}
}

func TestStreamSuspiciousIPsDefaultThreshold(t *testing.T) {
	cleanEvents(t)
	srv := newTestServer()

	// Seed exactly 5 failures -- the default threshold.
	for i := range 5 {
		_, err := srv.IngestEvent(context.Background(), &authlogv1.IngestEventRequest{
			UserId:    "w" + string(rune('0'+i)),
			IpAddress: "10.4.4.4",
			EventType: "failed_login",
		})
		if err != nil {
			t.Fatalf("seed error: %v", err)
		}
	}

	// min_failures: 0 triggers the default threshold of 5 inside the handler.
	stream := newMockStream()
	err := srv.StreamSuspiciousIPs(&authlogv1.StreamSuspiciousIPsRequest{MinFailures: 0}, stream)
	if err != nil {
		t.Fatalf("StreamSuspiciousIPs() error: %v", err)
	}
	if len(stream.results) != 1 {
		t.Fatalf("got %d results, want 1", len(stream.results))
	}
}
