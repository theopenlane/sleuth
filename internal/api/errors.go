package api

import "errors"

var (
	// ErrInvalidRequestBody is returned when the request body cannot be decoded
	ErrInvalidRequestBody = errors.New("invalid request body")
	// ErrDomainOrEmailRequired is returned when neither domain nor email is provided
	ErrDomainOrEmailRequired = errors.New("domain or email required")
	// ErrInvalidEmailFormat is returned when the email address format is invalid
	ErrInvalidEmailFormat = errors.New("invalid email format")
	// ErrIntelNotAvailable is returned when the intel manager is not configured
	ErrIntelNotAvailable = errors.New("threat intelligence not available")
	// ErrIntelNotConfigured is returned when the intel manager is nil
	ErrIntelNotConfigured = errors.New("intel manager not configured")
	// ErrEmailOrDomainRequired is returned when neither email nor domain is provided for intel check
	ErrEmailOrDomainRequired = errors.New("email or domain required")
	// ErrUnsupportedIndicatorType is returned when an unrecognized indicator type is provided
	ErrUnsupportedIndicatorType = errors.New("unsupported indicator type")
	// ErrMultipleJSONObjects is returned when the request body contains more than one JSON object
	ErrMultipleJSONObjects = errors.New("request body must contain a single JSON object")
	// ErrEnricherNotConfigured is returned when the Cloudflare enrichment client is nil
	ErrEnricherNotConfigured = errors.New("domain enrichment not configured")
	// ErrDomainRequired is returned when no domain or email is provided for enrichment
	ErrDomainRequired = errors.New("domain or email required for enrichment")
	// ErrComplianceDiscoveryFailed is returned when compliance page discovery encounters a fatal error
	ErrComplianceDiscoveryFailed = errors.New("compliance discovery failed")
)
