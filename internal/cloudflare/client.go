package cloudflare

import (
	"fmt"
	"net/http"
	"time"
)

const (
	// defaultBaseURL is the root endpoint for the Cloudflare API
	defaultBaseURL = "https://api.cloudflare.com/client/v4"
	// defaultRequestTimeout is the default timeout for Cloudflare API requests.
	// Browser rendering with SPA wait (networkidle2) can take 30-45 seconds,
	// so this must exceed the rendering time.
	defaultRequestTimeout = 60 * time.Second
	// browserNavigationTimeout is the Puppeteer-level navigation timeout in
	// milliseconds, controlling how long the browser waits for the waitUntil
	// condition (networkidle2). The default Puppeteer timeout is 30000ms which
	// is too short for heavy SPAs like Drata trust centers.
	browserNavigationTimeout = 45000
)

// Client provides access to Cloudflare APIs
type Client struct {
	accountID  string
	apiToken   string
	httpClient *http.Client
	baseURL    string
}

// Option configures the Client
type Option func(*Client)

// WithHTTPClient sets a custom HTTP client for the Cloudflare client
func WithHTTPClient(client *http.Client) Option {
	return func(c *Client) {
		if client != nil {
			c.httpClient = client
		}
	}
}

// WithBaseURL overrides the default Cloudflare API base URL
func WithBaseURL(url string) Option {
	return func(c *Client) {
		if url != "" {
			c.baseURL = url
		}
	}
}

// New creates a new Cloudflare client with the provided account ID and API token
func New(accountID, apiToken string, opts ...Option) (*Client, error) {
	if accountID == "" {
		return nil, ErrMissingAccountID
	}

	if apiToken == "" {
		return nil, ErrMissingAPIToken
	}

	client := &Client{
		accountID:  accountID,
		apiToken:   apiToken,
		httpClient: &http.Client{Timeout: defaultRequestTimeout},
		baseURL:    defaultBaseURL,
	}

	for _, opt := range opts {
		opt(client)
	}

	return client, nil
}

// apiURL constructs the full API URL for a given path under this account
func (c *Client) apiURL(path string) string {
	return fmt.Sprintf("%s/accounts/%s/%s", c.baseURL, c.accountID, path)
}
