package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/theopenlane/sleuth/internal/cloudflare"
	"github.com/theopenlane/sleuth/internal/slack"
)

func TestHandleEnrich_NotConfigured(t *testing.T) {
	handler := &Handler{
		scanner:     NewMockScanner(false, 0),
		enricher:    nil,
		maxBodySize: 1024,
	}

	body, _ := json.Marshal(EnrichRequest{Domain: "example.com"})
	req := httptest.NewRequest(http.MethodPost, "/api/enrich", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.handleEnrich(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status 503, got %d", w.Code)
	}
}

func TestHandleEnrich_MissingDomainAndEmail(t *testing.T) {
	cfServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer cfServer.Close()

	enricher, err := cloudflare.New("test-account", "test-token",
		cloudflare.WithHTTPClient(cfServer.Client()),
		cloudflare.WithBaseURL(cfServer.URL),
	)
	if err != nil {
		t.Fatalf("unexpected error creating enricher: %v", err)
	}

	handler := &Handler{
		scanner:     NewMockScanner(false, 0),
		enricher:    enricher,
		maxBodySize: 1024,
	}

	body, _ := json.Marshal(EnrichRequest{})
	req := httptest.NewRequest(http.MethodPost, "/api/enrich", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.handleEnrich(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

func TestHandleEnrich_ValidDomain(t *testing.T) {
	cfServer := newMockCloudflareServer(t, cloudflare.CompanyProfile{
		Name:        "Test Corp",
		Description: "A test company that tests things.",
		Industry:    "Testing",
	})
	defer cfServer.Close()

	enricher, err := cloudflare.New("test-account", "test-token",
		cloudflare.WithHTTPClient(cfServer.Client()),
		cloudflare.WithBaseURL(cfServer.URL),
	)
	if err != nil {
		t.Fatalf("unexpected error creating enricher: %v", err)
	}

	handler := &Handler{
		scanner:     NewMockScanner(false, 0),
		enricher:    enricher,
		maxBodySize: 1024,
	}

	body, _ := json.Marshal(EnrichRequest{Domain: "testcorp.com"})
	req := httptest.NewRequest(http.MethodPost, "/api/enrich", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.handleEnrich(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var resp EnrichResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !resp.Success {
		t.Error("expected success=true")
	}

	if resp.Data == nil {
		t.Fatal("expected data to be non-nil")
	}

	if resp.Data.Domain != "testcorp.com" {
		t.Errorf("expected domain testcorp.com, got %s", resp.Data.Domain)
	}

	if resp.Data.Profile.Name != "Test Corp" {
		t.Errorf("expected profile name Test Corp, got %s", resp.Data.Profile.Name)
	}

	if resp.Data.SlackNotified {
		t.Error("expected slack_notified=false when no notifier configured")
	}
}

func TestHandleEnrich_ValidEmail(t *testing.T) {
	cfServer := newMockCloudflareServer(t, cloudflare.CompanyProfile{
		Name:     "Email Corp",
		Industry: "Communications",
	})
	defer cfServer.Close()

	enricher, err := cloudflare.New("test-account", "test-token",
		cloudflare.WithHTTPClient(cfServer.Client()),
		cloudflare.WithBaseURL(cfServer.URL),
	)
	if err != nil {
		t.Fatalf("unexpected error creating enricher: %v", err)
	}

	handler := &Handler{
		scanner:     NewMockScanner(false, 0),
		enricher:    enricher,
		maxBodySize: 1024,
	}

	body, _ := json.Marshal(EnrichRequest{Email: "matt@emailcorp.com"})
	req := httptest.NewRequest(http.MethodPost, "/api/enrich", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.handleEnrich(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var resp EnrichResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Data.Domain != "emailcorp.com" {
		t.Errorf("expected domain emailcorp.com, got %s", resp.Data.Domain)
	}

	if resp.Data.Email != "matt@emailcorp.com" {
		t.Errorf("expected email matt@emailcorp.com, got %s", resp.Data.Email)
	}
}

func TestHandleEnrich_WithSlackNotification(t *testing.T) {
	cfServer := newMockCloudflareServer(t, cloudflare.CompanyProfile{
		Name:        "Slack Corp",
		Description: "A company with Slack integration.",
		Industry:    "SaaS",
		Products:    []string{"Widget A"},
		Location:    "NYC",
	})
	defer cfServer.Close()

	slackReceived := false
	slackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		slackReceived = true
		w.WriteHeader(http.StatusOK)
	}))
	defer slackServer.Close()

	enricher, err := cloudflare.New("test-account", "test-token",
		cloudflare.WithHTTPClient(cfServer.Client()),
		cloudflare.WithBaseURL(cfServer.URL),
	)
	if err != nil {
		t.Fatalf("unexpected error creating enricher: %v", err)
	}

	notifier, err := slack.New(slackServer.URL, slack.WithHTTPClient(slackServer.Client()))
	if err != nil {
		t.Fatalf("unexpected error creating notifier: %v", err)
	}

	handler := &Handler{
		scanner:     NewMockScanner(false, 0),
		enricher:    enricher,
		notifier:    notifier,
		maxBodySize: 1024,
	}

	body, _ := json.Marshal(EnrichRequest{Email: "user@slackcorp.com"})
	req := httptest.NewRequest(http.MethodPost, "/api/enrich", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.handleEnrich(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var resp EnrichResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !resp.Data.SlackNotified {
		t.Error("expected slack_notified=true")
	}

	if !slackReceived {
		t.Error("expected Slack webhook to be called")
	}
}

func TestHandleEnrich_SlackOptOut(t *testing.T) {
	cfServer := newMockCloudflareServer(t, cloudflare.CompanyProfile{
		Name: "NoSlack Corp",
	})
	defer cfServer.Close()

	slackCalled := false
	slackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		slackCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	defer slackServer.Close()

	enricher, err := cloudflare.New("test-account", "test-token",
		cloudflare.WithHTTPClient(cfServer.Client()),
		cloudflare.WithBaseURL(cfServer.URL),
	)
	if err != nil {
		t.Fatalf("unexpected error creating enricher: %v", err)
	}

	notifier, err := slack.New(slackServer.URL, slack.WithHTTPClient(slackServer.Client()))
	if err != nil {
		t.Fatalf("unexpected error creating notifier: %v", err)
	}

	handler := &Handler{
		scanner:     NewMockScanner(false, 0),
		enricher:    enricher,
		notifier:    notifier,
		maxBodySize: 1024,
	}

	notifyFalse := false
	body, _ := json.Marshal(EnrichRequest{Domain: "noslack.com", NotifySlack: &notifyFalse})
	req := httptest.NewRequest(http.MethodPost, "/api/enrich", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.handleEnrich(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	if slackCalled {
		t.Error("expected Slack webhook NOT to be called when notify_slack=false")
	}

	var resp EnrichResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Data.SlackNotified {
		t.Error("expected slack_notified=false when opted out")
	}
}

func TestHandleEnrich_CloudflareError(t *testing.T) {
	cfServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer cfServer.Close()

	enricher, err := cloudflare.New("test-account", "test-token",
		cloudflare.WithHTTPClient(cfServer.Client()),
		cloudflare.WithBaseURL(cfServer.URL),
	)
	if err != nil {
		t.Fatalf("unexpected error creating enricher: %v", err)
	}

	handler := &Handler{
		scanner:     NewMockScanner(false, 0),
		enricher:    enricher,
		maxBodySize: 1024,
	}

	body, _ := json.Marshal(EnrichRequest{Domain: "fail.com"})
	req := httptest.NewRequest(http.MethodPost, "/api/enrich", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.handleEnrich(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("expected status 502, got %d", w.Code)
	}
}

func TestBuildEnrichmentSlackMessage(t *testing.T) {
	profile := cloudflare.CompanyProfile{
		Name:          "Acme Corp",
		Description:   "Builds widgets.",
		Industry:      "Manufacturing",
		Products:      []string{"Widget A", "Widget B"},
		Location:      "Denver, CO",
		EmployeeRange: "51-200",
	}

	msg := buildEnrichmentSlackMessage("acme.com", "user@acme.com", profile)

	if msg.Text == "" {
		t.Error("expected fallback text to be set")
	}

	if len(msg.Blocks) == 0 {
		t.Fatal("expected blocks to be populated")
	}

	if msg.Blocks[0].Type != "header" {
		t.Errorf("expected first block to be header, got %s", msg.Blocks[0].Type)
	}
}

func TestTruncateText(t *testing.T) {
	short := "hello"
	if truncateText(short, 100) != "hello" {
		t.Error("expected short text to remain unchanged")
	}

	long := "this is a very long string that should be truncated"
	result := truncateText(long, 20)
	if len(result) != 20 {
		t.Errorf("expected truncated length 20, got %d", len(result))
	}

	if result[len(result)-3:] != "..." {
		t.Error("expected truncated text to end with ...")
	}
}

// newMockCloudflareServer creates a test server that returns a successful browser rendering response
func newMockCloudflareServer(t *testing.T, profile cloudflare.CompanyProfile) *httptest.Server {
	t.Helper()

	type renderResponse struct {
		Success bool                     `json:"success"`
		Result  cloudflare.CompanyProfile `json:"result"`
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if err := json.NewEncoder(w).Encode(renderResponse{
			Success: true,
			Result:  profile,
		}); err != nil {
			t.Errorf("failed to encode mock response: %v", err)
		}
	}))
}
