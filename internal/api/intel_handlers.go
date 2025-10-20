package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/theopenlane/sleuth/internal/intel"
)

// IntelHydrateResponse represents the response from the hydrate endpoint.
type IntelHydrateResponse struct {
	Success bool                    `json:"success"`
	Summary *intel.HydrationSummary `json:"summary,omitempty"`
	Error   string                  `json:"error,omitempty"`
}

// IntelCheckRequest represents an intel scoring request.
type IntelCheckRequest struct {
	Email              string   `json:"email,omitempty"`
	Domain             string   `json:"domain,omitempty"`
	IndicatorTypes     []string `json:"indicator_types,omitempty"`
	IncludeResolvedIPs *bool    `json:"include_resolved_ips,omitempty"`
}

// IntelCheckResponse represents the scoring response.
type IntelCheckResponse struct {
	Success bool               `json:"success"`
	Data    *intel.ScoreResult `json:"data,omitempty"`
	Error   string             `json:"error,omitempty"`
}

// handleIntelHydrate triggers a fresh hydration of all configured intel feeds.
func (h *Handler) handleIntelHydrate(w http.ResponseWriter, r *http.Request) {
	if h.intel == nil {
		respondWithError(w, "Intel manager not configured", http.StatusServiceUnavailable)
		return
	}

	if h.maxBodySize > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, h.maxBodySize)
	}

	summary, err := h.intel.Hydrate(r.Context())
	status := http.StatusOK
	response := IntelHydrateResponse{
		Success: err == nil,
		Summary: &summary,
	}
	if err != nil {
		response.Error = err.Error()
		if errors.Is(err, context.Canceled) {
			status = http.StatusRequestTimeout
		} else {
			status = http.StatusInternalServerError
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(response)
}

// handleIntelCheck evaluates an email/domain against hydrated intelligence feeds.
func (h *Handler) handleIntelCheck(w http.ResponseWriter, r *http.Request) {
	if h.intel == nil {
		respondWithError(w, "Intel manager not configured", http.StatusServiceUnavailable)
		return
	}

	if h.maxBodySize > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, h.maxBodySize)
	}

	var req IntelCheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Email == "" && req.Domain == "" {
		respondWithError(w, "Email or domain required", http.StatusBadRequest)
		return
	}

	indicatorTypes := make([]intel.IndicatorType, 0, len(req.IndicatorTypes))
	seen := make(map[intel.IndicatorType]struct{})
	for _, raw := range req.IndicatorTypes {
		typ, err := intel.ParseIndicatorType(raw)
		if err != nil {
			respondWithError(w, fmt.Sprintf("Unsupported indicator type: %s", raw), http.StatusBadRequest)
			return
		}
		if _, exists := seen[typ]; exists {
			continue
		}
		seen[typ] = struct{}{}
		indicatorTypes = append(indicatorTypes, typ)
	}

	if len(indicatorTypes) == 0 {
		switch {
		case req.Email != "" && req.Domain == "":
			indicatorTypes = []intel.IndicatorType{intel.IndicatorTypeEmail, intel.IndicatorTypeDomain}
		case req.Domain != "" && req.Email == "":
			indicatorTypes = []intel.IndicatorType{intel.IndicatorTypeDomain}
		case req.Email != "" && req.Domain != "":
			indicatorTypes = []intel.IndicatorType{intel.IndicatorTypeEmail, intel.IndicatorTypeDomain}
		}
	}

	includeResolvedIPs := false
	if req.IncludeResolvedIPs != nil {
		includeResolvedIPs = *req.IncludeResolvedIPs
	} else if req.Domain != "" {
		for _, typ := range indicatorTypes {
			if typ == intel.IndicatorTypeIP || typ == intel.IndicatorTypeCIDR {
				includeResolvedIPs = true
				break
			}
		}
	}

	result, err := h.intel.Check(r.Context(), intel.CheckRequest{
		Email:              req.Email,
		Domain:             req.Domain,
		IndicatorTypes:     indicatorTypes,
		IncludeResolvedIPs: includeResolvedIPs,
	})
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, intel.ErrNotHydrated) {
			status = http.StatusConflict
		}
		response := IntelCheckResponse{
			Success: false,
			Error:   err.Error(),
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(response)
		return
	}

	response := IntelCheckResponse{
		Success: true,
		Data:    &result,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}
