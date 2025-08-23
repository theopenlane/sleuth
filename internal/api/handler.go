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
	"net/http"
	"strings"
	"time"

	"github.com/theopenlane/sleuth/internal/scanner"
	"github.com/theopenlane/sleuth/internal/types"
)

// Handler manages API endpoints
type Handler struct {
	scanner scanner.ScannerInterface
}

// HealthResponse represents the health check response
type HealthResponse struct {
	Status    string `json:"status" example:"healthy"`
	Service   string `json:"service" example:"sleuth"`
	Timestamp string `json:"timestamp" example:"2024-01-15T10:30:00Z"`
}

// handleHealth returns service health status
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
	json.NewEncoder(w).Encode(response)
}

// ScanRequest represents a domain scan request
type ScanRequest struct {
	Email  string `json:"email,omitempty" example:"user@example.com" description:"Email address to extract domain from"`
	Domain string `json:"domain,omitempty" example:"example.com" description:"Domain to analyze directly"`
}

// ScanResponse represents the scan response
type ScanResponse struct {
	Success bool                `json:"success" example:"true" description:"Whether the scan completed successfully"`
	Data    *types.ScanResult   `json:"data,omitempty" description:"Scan results when successful"`
	Error   string              `json:"error,omitempty" example:"Invalid domain format" description:"Error message when scan fails"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Success bool   `json:"success" example:"false"`
	Error   string `json:"error" example:"Invalid request body"`
}

// handleScan processes domain scan requests
//	@Summary		Scan domain
//	@Description	Performs comprehensive security and technology analysis on a domain
//	@Description	Accepts either an email address (domain extracted) or direct domain
//	@Tags			scan
//	@Accept			json
//	@Produce		json
//	@Param			request	body		ScanRequest	true	"Scan request containing email or domain"
//	@Success		200		{object}	ScanResponse
//	@Failure		400		{object}	ErrorResponse
//	@Failure		405		{object}	ErrorResponse
//	@Failure		500		{object}	ErrorResponse
//	@Router			/scan [post]
func (h *Handler) handleScan(w http.ResponseWriter, r *http.Request) {

	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondWithError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Extract domain from email or use provided domain
	domain := req.Domain
	if domain == "" && req.Email != "" {
		parts := strings.Split(req.Email, "@")
		if len(parts) != 2 {
			respondWithError(w, "Invalid email format", http.StatusBadRequest)
			return
		}
		domain = parts[1]
	}

	if domain == "" {
		respondWithError(w, "Domain or email required", http.StatusBadRequest)
		return
	}

	// Create context with scan metadata
	ctx := context.WithValue(r.Context(), "scan_time", time.Now().Unix())
	
	// Perform scan  
	result, err := h.scanner.ScanDomain(ctx, domain)
	if err != nil {
		respondWithError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Send response
	response := ScanResponse{
		Success: true,
		Data:    result,
	}
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// respondWithError sends an error response
func respondWithError(w http.ResponseWriter, message string, statusCode int) {
	response := ScanResponse{
		Success: false,
		Error:   message,
	}
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)
}