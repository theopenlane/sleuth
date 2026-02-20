package domain

import "errors"

var (
	// ErrInvalidEmailFormat is returned when the email format is not valid
	ErrInvalidEmailFormat = errors.New("invalid email format")
	// ErrInvalidURLFormat is returned when the URL format is not valid
	ErrInvalidURLFormat = errors.New("invalid URL format")
	// ErrInvalidDomainFormat is returned when the domain format is not valid
	ErrInvalidDomainFormat = errors.New("invalid domain format")
)
