package slack

import "errors"

var (
	// ErrMissingWebhookURL is returned when the Slack webhook URL is not configured
	ErrMissingWebhookURL = errors.New("slack webhook URL is required")
	// ErrNotificationFailed is returned when a Slack webhook request fails
	ErrNotificationFailed = errors.New("slack notification failed")
	// ErrUnexpectedStatus is returned when Slack returns an unexpected HTTP status
	ErrUnexpectedStatus = errors.New("unexpected slack webhook response status")
)
