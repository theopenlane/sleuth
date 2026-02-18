package api

import (
	"context"
	"errors"
	"net/http"
	"sort"

	"github.com/theopenlane/sleuth/internal/intel"
)

// IntelHydrateResponse represents the response from the hydrate endpoint.
type IntelHydrateResponse struct {
	// Success indicates whether the hydration completed successfully.
	Success bool `json:"success"`
	// Data holds the hydration summary when successful.
	Data *intel.HydrationSummary `json:"data,omitempty"`
	// Error is the normalized error payload when hydration fails.
	Error *Error `json:"error,omitempty"`
}

// IntelCheckRequest represents an intel scoring request.
type IntelCheckRequest struct {
	// Email is the email address to check against intel feeds.
	Email string `json:"email,omitempty"`
	// Domain is the domain to check against intel feeds.
	Domain string `json:"domain,omitempty"`
	// IndicatorTypes is the list of indicator types to evaluate.
	IndicatorTypes []string `json:"indicator_types,omitempty"`
	// IncludeResolvedIPs controls whether to resolve domain IPs for additional checks.
	IncludeResolvedIPs *bool `json:"include_resolved_ips,omitempty"`
}

// IntelCheckResponse represents the scoring response.
type IntelCheckResponse struct {
	// Success indicates whether the intel check completed successfully.
	Success bool `json:"success"`
	// Data holds the scoring result when the check is successful.
	Data *intel.ScoreResult `json:"data,omitempty"`
	// Error is the normalized error payload when the intel check fails.
	Error *Error `json:"error,omitempty"`
}

// handleIntelHydrate triggers a fresh hydration of all configured intel feeds.
func (h *Handler) handleIntelHydrate(w http.ResponseWriter, r *http.Request) {
	if h.intel == nil {
		respondIntelHydrateError(w, http.StatusServiceUnavailable, errCodeUnavailable, ErrIntelNotConfigured.Error())
		return
	}

	summary, err := h.intel.Hydrate(r.Context())
	if err != nil {
		status := http.StatusInternalServerError
		code := errCodeInternal

		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			status = http.StatusGatewayTimeout
			code = errCodeTimeout
		case errors.Is(err, intel.ErrNoUsableHydrationData):
			status = http.StatusServiceUnavailable
			code = errCodeUnavailable
		}

		respondIntelHydrateError(w, status, code, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, IntelHydrateResponse{
		Success: true,
		Data:    &summary,
	})
}

// handleIntelCheck evaluates an email/domain against hydrated intelligence feeds.
func (h *Handler) handleIntelCheck(w http.ResponseWriter, r *http.Request) {
	if h.intel == nil {
		respondIntelCheckError(w, http.StatusServiceUnavailable, errCodeUnavailable, ErrIntelNotConfigured.Error())
		return
	}

	if h.maxBodySize > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, h.maxBodySize)
	}

	var req IntelCheckRequest
	if err := decodeJSONBody(r, &req); err != nil {
		respondIntelCheckError(w, http.StatusBadRequest, errCodeInvalidRequest, ErrInvalidRequestBody.Error())
		return
	}

	if req.Email == "" && req.Domain == "" {
		respondIntelCheckError(w, http.StatusBadRequest, errCodeValidation, ErrEmailOrDomainRequired.Error())
		return
	}

	indicatorTypes, err := normalizeIndicatorTypes(req.IndicatorTypes)
	if err != nil {
		respondIntelCheckError(w, http.StatusBadRequest, errCodeValidation, err.Error())
		return
	}
	if len(indicatorTypes) == 0 {
		indicatorTypes = defaultIndicatorTypes(req.Email, req.Domain)
	}

	includeResolvedIPs := shouldIncludeResolvedIPs(req.IncludeResolvedIPs, req.Domain, indicatorTypes)

	result, err := h.intel.Check(r.Context(), intel.CheckRequest{
		Email:              req.Email,
		Domain:             req.Domain,
		IndicatorTypes:     indicatorTypes,
		IncludeResolvedIPs: includeResolvedIPs,
	})
	if err != nil {
		status := http.StatusInternalServerError
		code := errCodeInternal
		if errors.Is(err, intel.ErrNotHydrated) {
			status = http.StatusConflict
			code = errCodeConflict
		}

		respondIntelCheckError(w, status, code, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, IntelCheckResponse{
		Success: true,
		Data:    &result,
	})
}

func normalizeIndicatorTypes(values []string) ([]intel.IndicatorType, error) {
	normalized := make([]intel.IndicatorType, 0, len(values))
	seen := make(map[intel.IndicatorType]struct{}, len(values))

	for _, raw := range values {
		typ, err := intel.ParseIndicatorType(raw)
		if err != nil {
			return nil, ErrUnsupportedIndicatorType
		}

		if _, exists := seen[typ]; exists {
			continue
		}
		seen[typ] = struct{}{}
		normalized = append(normalized, typ)
	}

	sort.SliceStable(normalized, func(i, j int) bool {
		return normalized[i] < normalized[j]
	})

	return normalized, nil
}

func defaultIndicatorTypes(email, domain string) []intel.IndicatorType {
	switch {
	case email != "" && domain == "":
		return []intel.IndicatorType{intel.IndicatorTypeDomain, intel.IndicatorTypeEmail}
	case domain != "" && email == "":
		return []intel.IndicatorType{intel.IndicatorTypeDomain}
	case email != "" && domain != "":
		return []intel.IndicatorType{intel.IndicatorTypeDomain, intel.IndicatorTypeEmail}
	default:
		return nil
	}
}

func shouldIncludeResolvedIPs(explicit *bool, domain string, indicatorTypes []intel.IndicatorType) bool {
	if explicit != nil {
		return *explicit
	}
	if domain == "" {
		return false
	}

	for _, typ := range indicatorTypes {
		if typ == intel.IndicatorTypeIP || typ == intel.IndicatorTypeCIDR {
			return true
		}
	}

	return false
}

func respondIntelHydrateError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, IntelHydrateResponse{
		Success: false,
		Error: &Error{
			Code:    code,
			Message: message,
		},
	})
}

func respondIntelCheckError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, IntelCheckResponse{
		Success: false,
		Error: &Error{
			Code:    code,
			Message: message,
		},
	})
}
