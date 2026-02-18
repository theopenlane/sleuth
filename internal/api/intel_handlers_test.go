package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/theopenlane/sleuth/internal/intel"
)

func TestHandleIntelCheck(t *testing.T) {
	tmpDir := t.TempDir()

	feedData := `203.0.113.10
malicious.example.com
spam@example.com
`

	// Set up test HTTP server to serve feed data
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(feedData))
	}))
	t.Cleanup(server.Close)

	feedCfg := intel.FeedConfig{
		Feeds: []intel.Feed{
			{
				Name: "test_feed",
				URL:  server.URL,
				Type: []string{"suspicious", "c2"},
			},
		},
	}

	client := server.Client()
	client.Timeout = 5 * time.Second

	manager, err := intel.NewManager(
		feedCfg,
		intel.WithStorageDir(tmpDir),
		intel.WithHTTPClient(client),
	)
	if err != nil {
		t.Fatalf("failed to create intel manager: %v", err)
	}

	// Hydrate the manager with test data
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := manager.Hydrate(ctx); err != nil {
		t.Fatalf("failed to hydrate manager: %v", err)
	}

	handler := &Handler{
		scanner:     NewMockScanner(false, 0),
		intel:       manager,
		maxBodySize: 1024 * 1024,
	}

	testCases := []struct {
		name           string
		requestBody    string
		expectedStatus int
		checkResponse  func(t *testing.T, resp IntelCheckResponse)
	}{
		{
			name:           "check domain",
			requestBody:    `{"domain":"malicious.example.com"}`,
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, resp IntelCheckResponse) {
				if !resp.Success {
					t.Error("expected success=true")
				}
				if resp.Data.Score == 0 {
					t.Error("expected non-zero score")
				}
				if resp.Data.RiskLevel == "" {
					t.Error("expected risk level")
				}
				if resp.Data.Recommendation == "" {
					t.Error("expected recommendation")
				}
			},
		},
		{
			name:           "check email",
			requestBody:    `{"email":"spam@example.com"}`,
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, resp IntelCheckResponse) {
				if !resp.Success {
					t.Error("expected success=true")
				}
				if resp.Data.Score == 0 {
					t.Error("expected non-zero score")
				}
			},
		},
		{
			name:           "check both email and domain",
			requestBody:    `{"email":"user@example.com","domain":"malicious.example.com"}`,
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, resp IntelCheckResponse) {
				if !resp.Success {
					t.Error("expected success=true")
				}
			},
		},
		{
			name:           "missing email and domain",
			requestBody:    `{}`,
			expectedStatus: http.StatusBadRequest,
			checkResponse:  nil,
		},
		{
			name:           "invalid json",
			requestBody:    `{invalid json}`,
			expectedStatus: http.StatusBadRequest,
			checkResponse:  nil,
		},
		{
			name:           "invalid indicator type",
			requestBody:    `{"domain":"example.com","indicator_types":["invalid"]}`,
			expectedStatus: http.StatusBadRequest,
			checkResponse:  nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/intel/check", bytes.NewBufferString(tc.requestBody))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			handler.handleIntelCheck(w, req)

			if w.Code != tc.expectedStatus {
				t.Errorf("expected status %d, got %d", tc.expectedStatus, w.Code)
			}

			if tc.checkResponse != nil {
				var resp IntelCheckResponse
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				tc.checkResponse(t, resp)
			}
		})
	}
}

func TestHandleIntelCheckNotHydrated(t *testing.T) {
	feedCfg := intel.FeedConfig{
		Feeds: []intel.Feed{
			{
				Name: "test_feed",
				URL:  "http://localhost/feed",
				Type: []string{"suspicious"},
			},
		},
	}

	manager, err := intel.NewManager(
		feedCfg,
		intel.WithStorageDir(t.TempDir()),
	)
	if err != nil {
		t.Fatalf("failed to create intel manager: %v", err)
	}

	handler := &Handler{
		scanner:     NewMockScanner(false, 0),
		intel:       manager,
		maxBodySize: 1024 * 1024,
	}

	req := httptest.NewRequest(http.MethodPost, "/api/intel/check", bytes.NewBufferString(`{"domain":"example.com"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.handleIntelCheck(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("expected status 409 (Conflict), got %d", w.Code)
	}

	var resp IntelCheckResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Success {
		t.Error("expected success=false for not hydrated")
	}
	if resp.Error == nil {
		t.Fatal("expected error payload")
	}
	if resp.Error.Message != "threat intelligence feeds have not been hydrated" {
		t.Errorf("expected not hydrated error, got: %s", resp.Error.Message)
	}
}

func TestHandleIntelCheckNoManager(t *testing.T) {
	handler := &Handler{
		scanner:     NewMockScanner(false, 0),
		intel:       nil,
		maxBodySize: 1024 * 1024,
	}

	req := httptest.NewRequest(http.MethodPost, "/api/intel/check", bytes.NewBufferString(`{"domain":"example.com"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.handleIntelCheck(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status 503 (Service Unavailable), got %d", w.Code)
	}
}

func TestHandleIntelHydrate(t *testing.T) {
	tmpDir := t.TempDir()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("203.0.113.10\nmalicious.example.com\n"))
	}))
	t.Cleanup(server.Close)

	feedCfg := intel.FeedConfig{
		Feeds: []intel.Feed{
			{
				Name: "test_feed",
				URL:  server.URL,
				Type: []string{"suspicious"},
			},
		},
	}

	client := server.Client()
	client.Timeout = 5 * time.Second

	manager, err := intel.NewManager(
		feedCfg,
		intel.WithStorageDir(tmpDir),
		intel.WithHTTPClient(client),
	)
	if err != nil {
		t.Fatalf("failed to create intel manager: %v", err)
	}

	handler := &Handler{
		scanner:     NewMockScanner(false, 0),
		intel:       manager,
		maxBodySize: 1024 * 1024,
	}

	req := httptest.NewRequest(http.MethodPost, "/api/intel/hydrate", nil)
	w := httptest.NewRecorder()

	handler.handleIntelHydrate(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var resp IntelHydrateResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !resp.Success {
		t.Error("expected success=true")
	}
	if resp.Data == nil {
		t.Fatal("expected summary to be non-nil")
	}
	if resp.Data.TotalFeeds != 1 {
		t.Errorf("expected 1 feed, got %d", resp.Data.TotalFeeds)
	}
	if resp.Data.SuccessfulFeeds != 1 {
		t.Errorf("expected 1 successful feed, got %d", resp.Data.SuccessfulFeeds)
	}
	if resp.Data.TotalIndicators == 0 {
		t.Error("expected indicators to be ingested")
	}
}

func TestHandleIntelHydrateNoManager(t *testing.T) {
	handler := &Handler{
		scanner:     NewMockScanner(false, 0),
		intel:       nil,
		maxBodySize: 1024 * 1024,
	}

	req := httptest.NewRequest(http.MethodPost, "/api/intel/hydrate", nil)
	w := httptest.NewRecorder()

	handler.handleIntelHydrate(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status 503 (Service Unavailable), got %d", w.Code)
	}
}

func TestHandleIntelCheckWithFlags(t *testing.T) {
	tmpDir := t.TempDir()

	feedData := `disposable-email.com
`

	// Set up test HTTP server to serve feed data
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(feedData))
	}))
	t.Cleanup(server.Close)

	feedCfg := intel.FeedConfig{
		Feeds: []intel.Feed{
			{
				Name:       "disposable_emails",
				URL:        server.URL,
				Type:       []string{"disposable"},
				Indicators: []intel.IndicatorType{intel.IndicatorTypeDomain},
			},
		},
	}

	client := server.Client()
	client.Timeout = 5 * time.Second

	manager, err := intel.NewManager(
		feedCfg,
		intel.WithStorageDir(tmpDir),
		intel.WithHTTPClient(client),
	)
	if err != nil {
		t.Fatalf("failed to create intel manager: %v", err)
	}

	// Hydrate the manager with test data
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := manager.Hydrate(ctx); err != nil {
		t.Fatalf("failed to hydrate manager: %v", err)
	}

	handler := &Handler{
		scanner:     NewMockScanner(false, 0),
		intel:       manager,
		maxBodySize: 1024 * 1024,
	}

	req := httptest.NewRequest(http.MethodPost, "/api/intel/check", bytes.NewBufferString(`{"domain":"disposable-email.com"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.handleIntelCheck(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var resp IntelCheckResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !resp.Data.Flags.IsDisposableEmail {
		t.Error("expected is_disposable_email flag to be true")
	}
	if len(resp.Data.Reasons) == 0 {
		t.Error("expected reasons to be populated")
	}
}
