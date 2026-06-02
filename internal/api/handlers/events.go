package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/BennerG/auth-log-analyzer/internal/models"
	"github.com/BennerG/auth-log-analyzer/internal/service"
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
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.UserID == "" || req.IPAddress == "" || req.EventType == "" || req.Status == "" {
		http.Error(w, `{"error":"user_id, ip_address, event_type, and status are required"}`, http.StatusBadRequest)
		return
	}

	event, err := h.svc.CreateEvent(r.Context(), req)
	if err != nil {
		http.Error(w, `{"error":"failed to create event"}`, http.StatusInternalServerError)
		return
	}

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
			http.Error(w, `{"error":"limit must be a positive integer"}`, http.StatusBadRequest)
			return
		}
		limit = parsed
	}

	events, err := h.svc.ListEvents(r.Context(), userID, limit)
	if err != nil {
		http.Error(w, `{"error":"failed to list events"}`, http.StatusInternalServerError)
		return
	}

	// Return empty array instead of null when no results
	if events == nil {
		events = []models.AuthEvent{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(events)
}
