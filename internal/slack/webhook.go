package slack

import (
	"context"
	"fmt"
	"net/http"

	"github.com/theopenlane/httpsling"
)

// Message represents a Slack webhook message payload
type Message struct {
	// Text is the fallback text for the notification
	Text string `json:"text"`
	// Blocks holds the rich layout blocks for the message
	Blocks []Block `json:"blocks,omitempty"`
}

// Block represents a Slack Block Kit block
type Block struct {
	// Type is the block type (section, divider, header, etc.)
	Type string `json:"type"`
	// Text is the text object for this block
	Text *TextObject `json:"text,omitempty"`
	// Fields holds multiple text objects for section blocks
	Fields []TextObject `json:"fields,omitempty"`
}

// TextObject represents a Slack text object
type TextObject struct {
	// Type is the text type (plain_text or mrkdwn)
	Type string `json:"type"`
	// Text is the actual text content
	Text string `json:"text"`
}

// Send posts a message to the configured Slack webhook
func (c *Client) Send(ctx context.Context, msg Message) error {
	requester := httpsling.MustNew(
		httpsling.URL(c.webhookURL),
		httpsling.Post(),
		httpsling.JSONBody(msg),
		httpsling.WithHTTPClient(c.httpClient),
	)

	resp, err := requester.SendWithContext(ctx)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNotificationFailed, err)
	}
	defer resp.Body.Close() //nolint:errcheck // response body close error is non-critical

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: status %d", ErrUnexpectedStatus, resp.StatusCode)
	}

	return nil
}
