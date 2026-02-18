package slack

import (
	"net/http"
	"time"
)

// defaultRequestTimeout is the default timeout for Slack webhook requests
const defaultRequestTimeout = 10 * time.Second

// Client sends notifications to Slack via incoming webhooks
type Client struct {
	webhookURL string
	httpClient *http.Client
}

// Option configures the Client
type Option func(*Client)

// WithHTTPClient sets a custom HTTP client for the Slack client
func WithHTTPClient(client *http.Client) Option {
	return func(c *Client) {
		if client != nil {
			c.httpClient = client
		}
	}
}

// New creates a new Slack webhook client
func New(webhookURL string, opts ...Option) (*Client, error) {
	if webhookURL == "" {
		return nil, ErrMissingWebhookURL
	}

	client := &Client{
		webhookURL: webhookURL,
		httpClient: &http.Client{Timeout: defaultRequestTimeout},
	}

	for _, opt := range opts {
		opt(client)
	}

	return client, nil
}
