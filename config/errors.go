package config

import "errors"

var (
	// ErrConfigUnmarshal is returned when config unmarshalling fails
	ErrConfigUnmarshal = errors.New("failed to unmarshal configuration")
)
