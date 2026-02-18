package cloudflare

import "errors"

var (
	// ErrMissingAccountID is returned when the Cloudflare account ID is not configured
	ErrMissingAccountID = errors.New("cloudflare account ID is required")
	// ErrMissingAPIToken is returned when the Cloudflare API token is not configured
	ErrMissingAPIToken = errors.New("cloudflare API token is required")
	// ErrRequestFailed is returned when a Cloudflare API request fails
	ErrRequestFailed = errors.New("cloudflare API request failed")
	// ErrUnexpectedStatus is returned when the Cloudflare API returns an unexpected HTTP status
	ErrUnexpectedStatus = errors.New("unexpected cloudflare API response status")
	// ErrRenderingFailed is returned when the browser rendering result indicates failure
	ErrRenderingFailed = errors.New("cloudflare browser rendering failed")
)
