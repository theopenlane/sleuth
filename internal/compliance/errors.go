package compliance

import "errors"

var (
	// ErrInvalidDomain is returned when the provided domain is empty or malformed
	ErrInvalidDomain = errors.New("invalid domain for compliance discovery")
	// ErrHomepageFetchFailed is returned when the homepage cannot be fetched for link extraction
	ErrHomepageFetchFailed = errors.New("failed to fetch homepage for link extraction")
)
