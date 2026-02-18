package api

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/rs/zerolog/log"
)

const (
	errCodeInvalidRequest = "invalid_request"
	errCodeValidation     = "validation_failed"
	errCodeInternal       = "internal_error"
	errCodeUnavailable    = "service_unavailable"
	errCodeTimeout        = "timeout"
	errCodeConflict       = "conflict"
)

// Error represents a normalized API error response.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// decodeJSONBody decodes a request body with strict unknown-field and trailing-token checks.
func decodeJSONBody(r *http.Request, dst any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(dst); err != nil {
		return err
	}

	var trailing json.RawMessage
	if err := dec.Decode(&trailing); err != io.EOF {
		return ErrMultipleJSONObjects
	}

	return nil
}

// writeJSON writes a JSON response and logs serialization failures.
func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Error().Err(err).Int("status", status).Msg("failed to encode JSON response")
	}
}
