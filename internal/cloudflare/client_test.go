package cloudflare

import (
	"net/http"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	client, err := New("account-123", "token-abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if client.accountID != "account-123" {
		t.Errorf("expected account ID account-123, got %s", client.accountID)
	}

	if client.apiToken != "token-abc" {
		t.Errorf("expected API token token-abc, got %s", client.apiToken)
	}

	if client.httpClient == nil {
		t.Fatal("expected default HTTP client to be set")
	}
}

func TestNew_MissingAccountID(t *testing.T) {
	_, err := New("", "token-abc")
	if err == nil {
		t.Fatal("expected error for missing account ID")
	}

	if err != ErrMissingAccountID {
		t.Errorf("expected ErrMissingAccountID, got %v", err)
	}
}

func TestNew_MissingAPIToken(t *testing.T) {
	_, err := New("account-123", "")
	if err == nil {
		t.Fatal("expected error for missing API token")
	}

	if err != ErrMissingAPIToken {
		t.Errorf("expected ErrMissingAPIToken, got %v", err)
	}
}

func TestNew_WithHTTPClient(t *testing.T) {
	customTimeout := 60 * time.Second
	customClient := &http.Client{Timeout: customTimeout}

	client, err := New("account-123", "token-abc", WithHTTPClient(customClient))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if client.httpClient != customClient {
		t.Error("expected custom HTTP client to be set")
	}

	if client.httpClient.Timeout != customTimeout {
		t.Errorf("expected timeout %v, got %v", customTimeout, client.httpClient.Timeout)
	}
}

func TestNew_WithNilHTTPClient(t *testing.T) {
	client, err := New("account-123", "token-abc", WithHTTPClient(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if client.httpClient == nil {
		t.Fatal("expected default HTTP client to remain when nil is passed")
	}
}

func TestAPIURL(t *testing.T) {
	client, err := New("my-account", "my-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := client.apiURL("browser-rendering/json")
	expected := "https://api.cloudflare.com/client/v4/accounts/my-account/browser-rendering/json"

	if got != expected {
		t.Errorf("expected %s, got %s", expected, got)
	}
}
