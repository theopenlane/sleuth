// Package api provides HTTP handlers for the Sleuth domain analysis service
//
//	@title			Sleuth API
//	@version		1.0
//	@description	Domain analysis sidecar service for security and technology discovery
//	@termsOfService	http://swagger.io/terms/
//
//	@contact.name	Openlane Support
//	@contact.url	https://github.com/theopenlane/sleuth
//	@contact.email	support@openlane.io
//
//	@license.name	Apache 2.0
//	@license.url	http://www.apache.org/licenses/LICENSE-2.0.html
//
//	@host		localhost:8080
//	@BasePath	/api
//
//	@schemes	http https
package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/theopenlane/sleuth/internal/cloudflare"
	"github.com/theopenlane/sleuth/internal/compliance"
	"github.com/theopenlane/sleuth/internal/intel"
	"github.com/theopenlane/sleuth/internal/scanner"
	"github.com/theopenlane/sleuth/internal/slack"
	"github.com/theopenlane/sleuth/internal/types"
)

// Handler manages API request handling for the sleuth service.
type Handler struct {
	// scanner performs domain security analysis.
	scanner scanner.Interface
	// intel provides threat intelligence scoring.
	intel *intel.Manager
	// enricher provides domain enrichment via Cloudflare Browser Rendering.
	enricher *cloudflare.Client
	// discoverer performs compliance page discovery via httpx.
	discoverer compliance.Discoverer
	// notifier sends notifications to Slack via webhook.
	notifier *slack.Client
	// maxBodySize limits the size of incoming request bodies.
	maxBodySize int64
	// scanTimeout is the maximum duration for a scan operation.
	scanTimeout time.Duration
}

// HealthResponse represents the health check response.
type HealthResponse struct {
	// Status is the current health status of the service.
	Status string `json:"status" example:"healthy"`
	// Service is the name of the service reporting health.
	Service string `json:"service" example:"sleuth"`
	// Timestamp is the UTC time the health check was performed.
	Timestamp string `json:"timestamp" example:"2024-01-15T10:30:00Z"`
}

// handleHealth returns service health status.
//
//	@Summary		Health check
//	@Description	Returns the health status of the Sleuth service
//	@Tags			health
//	@Produce		json
//	@Success		200	{object}	HealthResponse
//	@Router			/health [get]
func (h *Handler) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, HealthResponse{
		Status:    "healthy",
		Service:   "sleuth",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
}

// ScanRequest represents a domain scan request.
type ScanRequest struct {
	// Email is the email address to check or extract domain from.
	Email string `json:"email,omitempty" example:"user@example.com" description:"Email address to check or extract domain from"`
	// Domain is the domain to analyze directly.
	Domain string `json:"domain,omitempty" example:"example.com" description:"Domain to analyze directly"`
	// ScanDomain controls whether to also perform full domain infrastructure scan when an email is provided.
	ScanDomain bool `json:"scan_domain,omitempty" example:"false" description:"When email provided, also perform full domain infrastructure scan"`
}

// ScanResponse represents the scan response.
type ScanResponse struct {
	// Success indicates whether the scan completed successfully.
	Success bool `json:"success" example:"true" description:"Whether the scan completed successfully"`
	// Data holds the scan results when the scan is successful.
	Data *types.ScanResult `json:"data,omitempty" description:"Scan results when successful"`
	// Error is the normalized error payload when the scan fails.
	Error *Error `json:"error,omitempty" description:"Error payload when scan fails"`
}

// ErrorResponse represents an error response.
type ErrorResponse struct {
	// Success indicates whether the request was successful.
	Success bool `json:"success" example:"false"`
	// Error is the normalized error payload.
	Error *Error `json:"error" description:"Error payload"`
}

// handleScan processes domain and email scan requests.
//
//	@Summary		Scan domain or email
//	@Description	Performs security analysis on domain, email, or both
//	@Description	- Domain only: Full infrastructure scan
//	@Description	- Email only: Quick threat intelligence check
//	@Description	- Email with scan_domain=true: Intel check + full domain scan
//	@Tags			scan
//	@Accept			json
//	@Produce		json
//	@Param			request	body		ScanRequest	true	"Scan request with email and/or domain"
//	@Success		200		{object}	ScanResponse
//	@Failure		400		{object}	ErrorResponse
//	@Failure		405		{object}	ErrorResponse
//	@Failure		500		{object}	ErrorResponse
//	@Router			/scan [post]
func (h *Handler) handleScan(w http.ResponseWriter, r *http.Request) {
	if h.maxBodySize > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, h.maxBodySize)
	}

	var req ScanRequest
	if err := decodeJSONBody(r, &req); err != nil {
		respondScanError(w, http.StatusBadRequest, errCodeInvalidRequest, ErrInvalidRequestBody.Error())
		return
	}

	if req.Domain == "" && req.Email == "" {
		respondScanError(w, http.StatusBadRequest, errCodeValidation, ErrDomainOrEmailRequired.Error())
		return
	}

	scanCtx, cancel := context.WithTimeout(r.Context(), h.scanTimeout)
	defer cancel()

	var (
		result  *types.ScanResult
		scanErr error
	)

	switch {
	case req.Domain != "":
		result, scanErr = h.scanner.ScanDomain(scanCtx, req.Domain)
	case req.Email != "" && !req.ScanDomain:
		result, scanErr = h.performEmailCheck(scanCtx, req.Email)
	case req.Email != "" && req.ScanDomain:
		result, scanErr = h.performEmailAndDomainScan(scanCtx, req.Email)
	}

	if scanErr != nil {
		respondScanError(
			w,
			scanErrorStatus(scanErr),
			scanErrorCode(scanErr),
			scanErr.Error(),
		)
		return
	}

	writeJSON(w, http.StatusOK, ScanResponse{
		Success: true,
		Data:    result,
	})
}

// expectedEmailParts is the number of parts expected when splitting an email address on "@".
const expectedEmailParts = 2

// performEmailCheck checks email against threat intelligence feeds only.
func (h *Handler) performEmailCheck(ctx context.Context, email string) (*types.ScanResult, error) {
	domain, err := extractEmailDomain(email)
	if err != nil {
		return nil, err
	}

	if h.intel == nil {
		return nil, ErrIntelNotAvailable
	}

	score, err := h.intel.Check(ctx, intel.CheckRequest{
		Email:  email,
		Domain: domain,
	})
	if err != nil {
		log.Warn().Err(err).Str("email", email).Msg("intel check failed")
		return nil, err
	}

	return &types.ScanResult{
		Domain:     domain,
		Email:      email,
		ScannedAt:  fmt.Sprintf("%d", time.Now().Unix()),
		Results:    []types.CheckResult{},
		IntelScore: score,
	}, nil
}

// performEmailAndDomainScan checks email and performs full domain scan.
func (h *Handler) performEmailAndDomainScan(ctx context.Context, email string) (*types.ScanResult, error) {
	domain, err := extractEmailDomain(email)
	if err != nil {
		return nil, err
	}

	result, err := h.scanner.ScanDomain(ctx, domain)
	if err != nil {
		return nil, err
	}

	result.Email = email

	if h.intel != nil {
		score, intelErr := h.intel.Check(ctx, intel.CheckRequest{
			Email:  email,
			Domain: domain,
		})
		if intelErr != nil {
			log.Warn().Err(intelErr).Str("email", email).Msg("intel check failed during combined scan")
		} else {
			result.IntelScore = score
		}
	}

	return result, nil
}

// extractEmailDomain validates an email input and returns its domain component.
func extractEmailDomain(email string) (string, error) {
	parts := strings.Split(strings.TrimSpace(email), "@")
	if len(parts) != expectedEmailParts || parts[0] == "" || parts[1] == "" {
		return "", ErrInvalidEmailFormat
	}
	return strings.ToLower(parts[1]), nil
}

func respondScanError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, ScanResponse{
		Success: false,
		Error: &Error{
			Code:    code,
			Message: message,
		},
	})
}

func scanErrorStatus(err error) int {
	switch {
	case errors.Is(err, scanner.ErrInvalidDomain),
		errors.Is(err, ErrInvalidEmailFormat),
		errors.Is(err, ErrDomainOrEmailRequired),
		errors.Is(err, ErrInvalidRequestBody):
		return http.StatusBadRequest
	case errors.Is(err, ErrIntelNotConfigured),
		errors.Is(err, ErrIntelNotAvailable):
		return http.StatusServiceUnavailable
	case errors.Is(err, intel.ErrNotHydrated):
		return http.StatusConflict
	case errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded):
		return http.StatusGatewayTimeout
	default:
		return http.StatusInternalServerError
	}
}

func scanErrorCode(err error) string {
	switch {
	case errors.Is(err, scanner.ErrInvalidDomain),
		errors.Is(err, ErrInvalidEmailFormat),
		errors.Is(err, ErrDomainOrEmailRequired),
		errors.Is(err, ErrInvalidRequestBody):
		return errCodeValidation
	case errors.Is(err, ErrIntelNotConfigured),
		errors.Is(err, ErrIntelNotAvailable):
		return errCodeUnavailable
	case errors.Is(err, intel.ErrNotHydrated):
		return errCodeConflict
	case errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded):
		return errCodeTimeout
	default:
		return errCodeInternal
	}
}
