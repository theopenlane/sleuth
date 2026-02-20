package intel

import "errors"

var (
	// ErrNotHydrated is returned when a scoring request is made before the feeds are hydrated
	ErrNotHydrated = errors.New("threat intelligence feeds have not been hydrated")
	// ErrNoFeedsDefined is returned when the feed configuration contains no feeds
	ErrNoFeedsDefined = errors.New("feed configuration has no feeds defined")
	// ErrNoUsableHydrationData is returned when hydration completed without producing usable indicators
	ErrNoUsableHydrationData = errors.New("hydration produced no usable indicator data")
	// ErrEmptyIndicatorType is returned when an empty indicator type is provided
	ErrEmptyIndicatorType = errors.New("indicator type cannot be empty")
	// ErrUnexpectedFeedStatus is returned when a feed download returns an unexpected HTTP status
	ErrUnexpectedFeedStatus = errors.New("unexpected feed response status")
)
