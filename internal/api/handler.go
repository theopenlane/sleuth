// Package api provides HTTP handlers for the Sleuth domain analysis service.
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
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/theopenlane/sleuth/internal/intel"
	"github.com/theopenlane/sleuth/internal/scanner"
	"github.com/theopenlane/sleuth/internal/types"
)

// contextKey is a custom type for context keys to avoid collisions
type contextKey string

const scanTimeKey contextKey = "scan_time"

// Handler manages API endpoints
type Handler struct {
	scanner      scanner.ScannerInterface
	intel        *intel.Manager
	maxBodySize  int64
	scanTimeout  time.Duration
}

// HealthResponse represents the health check response
type HealthResponse struct {
	Status    string `json:"status" example:"healthy"`
	Service   string `json:"service" example:"sleuth"`
	Timestamp string `json:"timestamp" example:"2024-01-15T10:30:00Z"`
}

// handleHealth returns service health status
//
//	@Summary		Health check
//	@Description	Returns the health status of the Sleuth service
//	@Tags			health
//	@Produce		json
//	@Success		200	{object}	HealthResponse
//	@Router			/health [get]
func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	response := HealthResponse{
		Status:    "healthy",
		Service:   "sleuth",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

// ScanRequest represents a domain scan request
type ScanRequest struct {
	Email      string `json:"email,omitempty" example:"user@example.com" description:"Email address to check or extract domain from"`
	Domain     string `json:"domain,omitempty" example:"example.com" description:"Domain to analyze directly"`
	ScanDomain bool   `json:"scan_domain,omitempty" example:"false" description:"When email provided, also perform full domain infrastructure scan"`
}

// ScanResponse represents the scan response
type ScanResponse struct {
	Success bool              `json:"success" example:"true" description:"Whether the scan completed successfully"`
	Data    *types.ScanResult `json:"data,omitempty" description:"Scan results when successful"`
	Error   string            `json:"error,omitempty" example:"Invalid domain format" description:"Error message when scan fails"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Success bool   `json:"success" example:"false"`
	Error   string `json:"error" example:"Invalid request body"`
}

// handleScan processes domain and email scan requests
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate input
	if req.Domain == "" && req.Email == "" {
		respondWithError(w, "Domain or email required", http.StatusBadRequest)
		return
	}

	// Create context with scan timeout
	ctx, cancel := context.WithTimeout(context.Background(), h.scanTimeout)
	defer cancel()
	ctx = context.WithValue(ctx, scanTimeKey, time.Now().Unix())

	// Determine scan mode
	var result *types.ScanResult
	var err error

	if req.Domain != "" {
		// Mode 1: Domain-only scan (full infrastructure analysis)
		result, err = h.scanner.ScanDomain(ctx, req.Domain)
		if err != nil {
			respondWithError(w, err.Error(), http.StatusBadRequest)
			return
		}
	} else if req.Email != "" && !req.ScanDomain {
		// Mode 2: Email-only (quick intel check)
		result, err = h.performEmailCheck(ctx, req.Email)
		if err != nil {
			respondWithError(w, err.Error(), http.StatusBadRequest)
			return
		}
	} else if req.Email != "" && req.ScanDomain {
		// Mode 3: Email + domain scan (intel + full infrastructure)
		result, err = h.performEmailAndDomainScan(ctx, req.Email)
		if err != nil {
			respondWithError(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	// Send response
	response := ScanResponse{
		Success: true,
		Data:    result,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// performEmailCheck checks email against threat intelligence feeds only
func (h *Handler) performEmailCheck(ctx context.Context, email string) (*types.ScanResult, error) {
	// Validate email format
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid email format")
	}
	domain := parts[1]

	// Check if intel manager is available
	if h.intel == nil {
		return nil, fmt.Errorf("threat intelligence not available")
	}

	// Perform intel check
	score, err := h.intel.Check(ctx, intel.CheckRequest{
		Email:  email,
		Domain: domain,
	})
	if err != nil {
		return nil, fmt.Errorf("intel check failed: %w", err)
	}

	// Build scan result
	result := &types.ScanResult{
		Domain:     domain,
		Email:      email,
		ScannedAt:  fmt.Sprintf("%d", time.Now().Unix()),
		Results:    []types.CheckResult{},
		IntelScore: score,
	}

	return result, nil
}

// performEmailAndDomainScan checks email and performs full domain scan
func (h *Handler) performEmailAndDomainScan(ctx context.Context, email string) (*types.ScanResult, error) {
	// Validate email format
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid email format")
	}
	domain := parts[1]

	// Perform domain scan
	result, err := h.scanner.ScanDomain(ctx, domain)
	if err != nil {
		return nil, err
	}

	// Add email to result
	result.Email = email

	// Add intel check if available
	if h.intel != nil {
		score, err := h.intel.Check(ctx, intel.CheckRequest{
			Email:  email,
			Domain: domain,
		})
		if err == nil {
			result.IntelScore = score
		}
		// Don't fail the whole scan if intel check fails
	}

	return result, nil
}

// respondWithError sends an error response
func respondWithError(w http.ResponseWriter, message string, statusCode int) {
	response := ScanResponse{
		Success: false,
		Error:   message,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(response)
}
