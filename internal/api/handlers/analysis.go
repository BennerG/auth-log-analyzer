package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/BennerG/auth-log-analyzer/internal/models"
	"github.com/BennerG/auth-log-analyzer/internal/service"
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
			http.Error(w, `{"error":"threshold must be a positive integer"}`, http.StatusBadRequest)
			return
		}
		threshold = parsed
	}

	since := 24 * time.Hour
	if s := r.URL.Query().Get("since_hours"); s != "" {
		parsed, err := strconv.Atoi(s)
		if err != nil || parsed <= 0 {
			http.Error(w, `{"error":"since_hours must be a positive integer"}`, http.StatusBadRequest)
			return
		}
		since = time.Duration(parsed) * time.Hour
	}

	ips, err := h.svc.GetSuspiciousIPs(r.Context(), threshold, since)
	if err != nil {
		http.Error(w, `{"error":"failed to get suspicious IPs"}`, http.StatusInternalServerError)
		return
	}

	if ips == nil {
		ips = []models.SuspiciousIP{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ips)
}

func (h *AnalysisHandler) UserActivity(w http.ResponseWriter, r *http.Request) {
	since := 24 * time.Hour
	if s := r.URL.Query().Get("since_hours"); s != "" {
		parsed, err := strconv.Atoi(s)
		if err != nil || parsed <= 0 {
			http.Error(w, `{"error":"since_hours must be a positive integer"}`, http.StatusBadRequest)
			return
		}
		since = time.Duration(parsed) * time.Hour
	}

	activity, err := h.svc.GetUserActivity(r.Context(), since)
	if err != nil {
		http.Error(w, `{"error":"failed to get user activity"}`, http.StatusInternalServerError)
		return
	}

	if activity == nil {
		activity = []models.UserActivity{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(activity)
}
