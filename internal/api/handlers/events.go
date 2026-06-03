package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/BennerG/auth-log-analyzer/internal/metrics"
	"github.com/BennerG/auth-log-analyzer/internal/models"
	"github.com/BennerG/auth-log-analyzer/internal/service"
	"github.com/rs/zerolog/log"
)

type EventHandler struct {
	svc *service.EventService
}

func NewEventHandler(svc *service.EventService) *EventHandler {
	return &EventHandler{svc: svc}
}

func (h *EventHandler) CreateEvent(w http.ResponseWriter, r *http.Request) {
	var req models.CreateEventRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Warn().Err(err).Msg("invalid request body")
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.UserID == "" || req.IPAddress == "" || req.EventType == "" || req.Status == "" {
		log.Warn().
			Str("user_id", req.UserID).
			Str("ip_address", req.IPAddress).
			Msg("missing required fields")
		http.Error(w, `{"error":"user_id, ip_address, event_type, and status are required"}`, http.StatusBadRequest)
		return
	}

	event, err := h.svc.CreateEvent(r.Context(), req)
	if err != nil {
		log.Error().Err(err).
			Str("user_id", req.UserID).
			Str("ip_address", req.IPAddress).
			Msg("failed to create event")
		http.Error(w, `{"error":"failed to create event"}`, http.StatusInternalServerError)
		return
	}

	// Increment domain metric
	metrics.AuthEventsIngested.WithLabelValues(
		string(event.EventType),
		string(event.Status),
	).Inc()

	log.Info().
		Int64("event_id", event.ID).
		Str("user_id", event.UserID).
		Str("ip_address", event.IPAddress).
		Str("event_type", string(event.EventType)).
		Str("status", string(event.Status)).
		Msg("auth event created")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(event)
}

func (h *EventHandler) ListEvents(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user_id")

	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		parsed, err := strconv.Atoi(l)
		if err != nil || parsed <= 0 {
			log.Warn().Str("limit", l).Msg("invalid limit parameter")
			http.Error(w, `{"error":"limit must be a positive integer"}`, http.StatusBadRequest)
			return
		}
		limit = parsed
	}

	events, err := h.svc.ListEvents(r.Context(), userID, limit)
	if err != nil {
		log.Error().Err(err).Str("user_id", userID).Msg("failed to list events")
		http.Error(w, `{"error":"failed to list events"}`, http.StatusInternalServerError)
		return
	}

	// Return empty array instead of null when no results
	if events == nil {
		events = []models.AuthEvent{}
	}

	log.Info().
		Str("user_id", userID).
		Int("count", len(events)).
		Msg("events listed")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(events)
}
