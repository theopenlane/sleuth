package slack

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSend_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}

		contentType := r.Header.Get("Content-Type")
		if !strings.HasPrefix(contentType, "application/json") {
			t.Errorf("expected Content-Type to start with application/json, got %s", contentType)
		}

		var msg Message
		if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
			t.Fatalf("failed to decode message: %v", err)
		}

		if msg.Text != "test message" {
			t.Errorf("expected text 'test message', got %s", msg.Text)
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := New(server.URL, WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	err = client.Send(context.Background(), Message{Text: "test message"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSend_WithBlocks(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var msg Message
		if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
			t.Fatalf("failed to decode message: %v", err)
		}

		if len(msg.Blocks) != 2 {
			t.Errorf("expected 2 blocks, got %d", len(msg.Blocks))
		}

		if msg.Blocks[0].Type != "header" {
			t.Errorf("expected first block type header, got %s", msg.Blocks[0].Type)
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := New(server.URL, WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	msg := Message{
		Text: "fallback",
		Blocks: []Block{
			{
				Type: "header",
				Text: &TextObject{Type: "plain_text", Text: "Header"},
			},
			{
				Type: "section",
				Text: &TextObject{Type: "mrkdwn", Text: "Body text"},
			},
		},
	}

	err = client.Send(context.Background(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSend_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client, err := New(server.URL, WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	err = client.Send(context.Background(), Message{Text: "test"})
	if err == nil {
		t.Fatal("expected error for server error response")
	}
}

func TestSend_RequestError(t *testing.T) {
	client, err := New("http://localhost:1/invalid", WithHTTPClient(&http.Client{}))
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	err = client.Send(context.Background(), Message{Text: "test"})
	if err == nil {
		t.Fatal("expected error for request failure")
	}
}
