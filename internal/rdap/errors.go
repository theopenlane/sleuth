package rdap

import "errors"

var (
	// ErrEmptyDomain is returned when an empty domain is provided for analysis
	ErrEmptyDomain = errors.New("domain must not be empty")
	// ErrNoRegistrationDate is returned when RDAP response contains no registration event
	ErrNoRegistrationDate = errors.New("no registration date found in RDAP response")
)
