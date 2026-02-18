package slack

import (
	"net/http"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	client, err := New("https://hooks.slack.com/services/T123/B456/xyz")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if client.webhookURL != "https://hooks.slack.com/services/T123/B456/xyz" {
		t.Errorf("expected webhook URL to be set, got %s", client.webhookURL)
	}

	if client.httpClient == nil {
		t.Fatal("expected default HTTP client to be set")
	}
}

func TestNew_MissingWebhookURL(t *testing.T) {
	_, err := New("")
	if err == nil {
		t.Fatal("expected error for missing webhook URL")
	}

	if err != ErrMissingWebhookURL {
		t.Errorf("expected ErrMissingWebhookURL, got %v", err)
	}
}

func TestNew_WithHTTPClient(t *testing.T) {
	customTimeout := 30 * time.Second
	customClient := &http.Client{Timeout: customTimeout}

	client, err := New("https://hooks.slack.com/test", WithHTTPClient(customClient))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if client.httpClient != customClient {
		t.Error("expected custom HTTP client to be set")
	}
}

func TestNew_WithNilHTTPClient(t *testing.T) {
	client, err := New("https://hooks.slack.com/test", WithHTTPClient(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if client.httpClient == nil {
		t.Fatal("expected default HTTP client to remain when nil is passed")
	}
}
