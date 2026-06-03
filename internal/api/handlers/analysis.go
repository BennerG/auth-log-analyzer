package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/BennerG/auth-log-analyzer/internal/models"
	"github.com/BennerG/auth-log-analyzer/internal/service"
	"github.com/rs/zerolog/log"
)

type AnalysisHandler struct {
	svc *service.EventService
}

func NewAnalysisHandler(svc *service.EventService) *AnalysisHandler {
	return &AnalysisHandler{svc: svc}
}

func (h *AnalysisHandler) SuspiciousIPs(w http.ResponseWriter, r *http.Request) {
	threshold := 5
	if t := r.URL.Query().Get("threshold"); t != "" {
		parsed, err := strconv.Atoi(t)
		if err != nil || parsed <= 0 {
			log.Warn().Str("threshold", t).Msg("invalid threshold parameter")
			http.Error(w, `{"error":"threshold must be a positive integer"}`, http.StatusBadRequest)
			return
		}
		threshold = parsed
	}

	since := 24 * time.Hour
	if s := r.URL.Query().Get("since_hours"); s != "" {
		parsed, err := strconv.Atoi(s)
		if err != nil || parsed <= 0 {
			log.Warn().Str("since_hours", s).Msg("invalid since_hours parameter")
			http.Error(w, `{"error":"since_hours must be a positive integer"}`, http.StatusBadRequest)
			return
		}
		since = time.Duration(parsed) * time.Hour
	}

	ips, err := h.svc.GetSuspiciousIPs(r.Context(), threshold, since)
	if err != nil {
		log.Error().Err(err).
			Int("threshold", threshold).
			Dur("since", since).
			Msg("failed to get suspicious IPs")
		http.Error(w, `{"error":"failed to get suspicious IPs"}`, http.StatusInternalServerError)
		return
	}

	if ips == nil {
		ips = []models.SuspiciousIP{}
	}

	log.Info().
		Int("count", len(ips)).
		Int("threshold", threshold).
		Dur("since", since).
		Msg("suspicious IPs query complete")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ips)
}

func (h *AnalysisHandler) UserActivity(w http.ResponseWriter, r *http.Request) {
	since := 24 * time.Hour
	if s := r.URL.Query().Get("since_hours"); s != "" {
		parsed, err := strconv.Atoi(s)
		if err != nil || parsed <= 0 {
			log.Warn().Str("since_hours", s).Msg("invalid since_hours parameter")
			http.Error(w, `{"error":"since_hours must be a positive integer"}`, http.StatusBadRequest)
			return
		}
		since = time.Duration(parsed) * time.Hour
	}

	activity, err := h.svc.GetUserActivity(r.Context(), since)
	if err != nil {
		log.Error().Err(err).Dur("since", since).Msg("failed to get user activity")
		http.Error(w, `{"error":"failed to get user activity"}`, http.StatusInternalServerError)
		return
	}

	if activity == nil {
		activity = []models.UserActivity{}
	}

	log.Info().
		Int("count", len(activity)).
		Dur("since", since).
		Msg("user activity query complete")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(activity)
}
