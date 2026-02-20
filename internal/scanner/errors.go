package scanner

import "errors"

var (
	// ErrInvalidDomain is returned when the provided domain cannot be parsed
	ErrInvalidDomain = errors.New("invalid domain")
	// ErrTooManyRedirects is returned when an HTTP request exceeds the redirect limit
	ErrTooManyRedirects = errors.New("too many redirects")
	// ErrFetchResponseBody is returned when the scanner cannot retrieve a response body from a host
	ErrFetchResponseBody = errors.New("unable to fetch response body")
)
