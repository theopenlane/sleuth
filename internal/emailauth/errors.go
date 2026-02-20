package emailauth

import "errors"

var (
	// ErrEmptyDomain is returned when an empty domain is provided for analysis
	ErrEmptyDomain = errors.New("domain must not be empty")
	// ErrDNSLookupFailed is returned when a DNS lookup fails during analysis
	ErrDNSLookupFailed = errors.New("DNS lookup failed")
)
