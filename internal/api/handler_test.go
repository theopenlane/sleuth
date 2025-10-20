package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/theopenlane/sleuth/internal/intel"
	"github.com/theopenlane/sleuth/internal/scanner"
	"github.com/theopenlane/sleuth/internal/types"
)

// MockScanner implements the scanner interface for testing
type MockScanner struct {
	shouldError bool
	delay       time.Duration
}

func NewMockScanner(shouldError bool, delay time.Duration) *MockScanner {
	return &MockScanner{
		shouldError: shouldError,
		delay:       delay,
	}
}

func (m *MockScanner) ScanDomain(ctx context.Context, domain string) (*types.ScanResult, error) {
	if m.delay > 0 {
		time.Sleep(m.delay)
	}

	if m.shouldError {
		return nil, fmt.Errorf("mock scanner error")
	}

	return &types.ScanResult{
		Domain:    domain,
		ScannedAt: "1234567890",
		DomainInfo: &types.DomainInfo{
			Domain: domain,
			TLD:    "com",
			SLD:    "example",
		},
		Results: []types.CheckResult{
			{
				CheckName: "test_check",
				Status:    "pass",
				Findings: []types.Finding{
					{
						Severity:    "info",
						Type:        "test",
						Description: "Test finding",
						Details:     "Test details",
					},
				},
			},
		},
	}, nil
}

func (m *MockScanner) Close() error {
	return nil
}

func TestHandleHealth(t *testing.T) {
	mockScanner := NewMockScanner(false, 0)
	handler := NewRouter(mockScanner, nil, 1024, 60*time.Second)

	req := httptest.NewRequest("GET", "/api/health", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]string
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response["status"] != "healthy" {
		t.Errorf("Expected status 'healthy', got %s", response["status"])
	}

	if response["service"] != "sleuth" {
		t.Errorf("Expected service 'sleuth', got %s", response["service"])
	}

	if response["timestamp"] == "" {
		t.Error("Expected non-empty timestamp")
	}
}

func TestHandleScan_ValidDomain(t *testing.T) {
	mockScanner := NewMockScanner(false, 0)
	handler := NewRouter(mockScanner, nil, 1024, 60*time.Second)

	requestBody := ScanRequest{
		Domain: "example.com",
	}

	body, _ := json.Marshal(requestBody)
	req := httptest.NewRequest("POST", "/api/scan", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response ScanResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if !response.Success {
		t.Errorf("Expected success=true, got %v", response.Success)
	}

	if response.Data == nil {
		t.Fatal("Expected scan data")
	}

	if response.Data.Domain != "example.com" {
		t.Errorf("Expected domain 'example.com', got %s", response.Data.Domain)
	}
}

func TestHandleScan_ValidEmail(t *testing.T) {
	mockScanner := NewMockScanner(false, 0)
	handler := NewRouter(mockScanner, nil, 1024, 60*time.Second)

	requestBody := ScanRequest{
		Email: "test@example.com",
	}

	body, _ := json.Marshal(requestBody)
	req := httptest.NewRequest("POST", "/api/scan", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response ScanResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if !response.Success {
		t.Errorf("Expected success=true, got %v", response.Success)
	}

	if response.Data.Domain != "example.com" {
		t.Errorf("Expected domain 'example.com', got %s", response.Data.Domain)
	}
}

func TestHandleScan_InvalidMethod(t *testing.T) {
	mockScanner := NewMockScanner(false, 0)
	handler := NewRouter(mockScanner, nil, 1024, 60*time.Second)

	req := httptest.NewRequest("GET", "/api/scan", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", w.Code)
	}
}

func TestHandleScan_InvalidJSON(t *testing.T) {
	mockScanner := NewMockScanner(false, 0)
	handler := NewRouter(mockScanner, nil, 1024, 60*time.Second)

	req := httptest.NewRequest("POST", "/api/scan", bytes.NewBufferString("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}

	var response ScanResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response.Success {
		t.Error("Expected success=false for invalid JSON")
	}

	if response.Error == "" {
		t.Error("Expected error message")
	}
}

func TestHandleScan_InvalidEmail(t *testing.T) {
	mockScanner := NewMockScanner(false, 0)
	handler := NewRouter(mockScanner, nil, 1024, 60*time.Second)

	requestBody := ScanRequest{
		Email: "invalid-email-format",
	}

	body, _ := json.Marshal(requestBody)
	req := httptest.NewRequest("POST", "/api/scan", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}

	var response ScanResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response.Success {
		t.Error("Expected success=false for invalid email")
	}
}

func TestHandleScan_MissingDomainAndEmail(t *testing.T) {
	mockScanner := NewMockScanner(false, 0)
	handler := NewRouter(mockScanner, nil, 1024, 60*time.Second)

	requestBody := ScanRequest{}

	body, _ := json.Marshal(requestBody)
	req := httptest.NewRequest("POST", "/api/scan", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}

	var response ScanResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response.Success {
		t.Error("Expected success=false when both domain and email are missing")
	}
}

func TestHandleScan_ScannerError(t *testing.T) {
	mockScanner := NewMockScanner(true, 0)
	handler := NewRouter(mockScanner, nil, 1024, 60*time.Second)

	requestBody := ScanRequest{
		Domain: "example.com",
	}

	body, _ := json.Marshal(requestBody)
	req := httptest.NewRequest("POST", "/api/scan", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}

	var response ScanResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response.Success {
		t.Error("Expected success=false when scanner returns error")
	}

	if response.Error == "" {
		t.Error("Expected error message when scanner fails")
	}
}

func TestRespondWithError(t *testing.T) {
	w := httptest.NewRecorder()

	respondWithError(w, "test error", http.StatusTeapot)

	if w.Code != http.StatusTeapot {
		t.Errorf("Expected status 418, got %d", w.Code)
	}

	var response ScanResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response.Success {
		t.Error("Expected success=false")
	}

	if response.Error != "test error" {
		t.Errorf("Expected error 'test error', got %s", response.Error)
	}

	if response.Data != nil {
		t.Error("Expected data to be nil on error")
	}
}

func TestHandleIntelCheck_NotHydrated(t *testing.T) {
	manager, cleanup := newTestIntelManager(t, "malicious.example.com\n")
	defer cleanup()

	handler := &Handler{
		intel:       manager,
		maxBodySize: 2048,
	}

	req := httptest.NewRequest("POST", "/api/intel/check", bytes.NewBufferString(`{"domain":"malicious.example.com"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.handleIntelCheck(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected status 409, got %d", w.Code)
	}
}

func TestHandleIntelCheck_InvalidIndicatorType(t *testing.T) {
	manager, cleanup := newTestIntelManager(t, "malicious.example.com\n")
	defer cleanup()

	handler := &Handler{
		intel:       manager,
		maxBodySize: 2048,
	}

	req := httptest.NewRequest("POST", "/api/intel/check", bytes.NewBufferString(`{"domain":"malicious.example.com","indicator_types":["invalid"]}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.handleIntelCheck(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestHandleIntelHydrateAndCheck(t *testing.T) {
	manager, cleanup := newTestIntelManager(t, "malicious.example.com\n")
	defer cleanup()

	handler := &Handler{
		intel:       manager,
		maxBodySize: 4096,
	}

	hydrateReq := httptest.NewRequest("POST", "/api/intel/hydrate", nil)
	hydrateResp := httptest.NewRecorder()
	handler.handleIntelHydrate(hydrateResp, hydrateReq)

	if hydrateResp.Code != http.StatusOK {
		t.Fatalf("expected hydrate status 200, got %d", hydrateResp.Code)
	}

	var hydrate IntelHydrateResponse
	if err := json.NewDecoder(hydrateResp.Body).Decode(&hydrate); err != nil {
		t.Fatalf("failed to decode hydrate response: %v", err)
	}
	if !hydrate.Success {
		t.Fatalf("expected hydrate success, got error: %s", hydrate.Error)
	}
	if hydrate.Summary == nil || hydrate.Summary.SuccessfulFeeds == 0 {
		t.Fatal("expected feed summary with successful hydration")
	}

	checkReq := httptest.NewRequest("POST", "/api/intel/check", bytes.NewBufferString(`{"domain":"malicious.example.com"}`))
	checkReq.Header.Set("Content-Type", "application/json")
	checkResp := httptest.NewRecorder()
	handler.handleIntelCheck(checkResp, checkReq)

	if checkResp.Code != http.StatusOK {
		t.Fatalf("expected check status 200, got %d", checkResp.Code)
	}

	var intelResp IntelCheckResponse
	if err := json.NewDecoder(checkResp.Body).Decode(&intelResp); err != nil {
		t.Fatalf("failed to decode intel check response: %v", err)
	}
	if !intelResp.Success {
		t.Fatalf("expected success response, got error: %s", intelResp.Error)
	}
	if intelResp.Data == nil || len(intelResp.Data.Matches) == 0 {
		t.Fatal("expected match data in response")
	}
	if intelResp.Data.Summary.FeedCount == 0 {
		t.Fatal("expected summary feed count in response")
	}
}

// Integration test with real scanner
func TestHandleScan_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	realScanner, err := scanner.New(
		scanner.WithMaxSubdomains(5),
		scanner.WithNucleiTemplates([]string{}), // Disable nuclei for testing
	)
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}
	defer realScanner.Close()

	handler := NewRouter(realScanner, nil, 1024, 60*time.Second)

	requestBody := ScanRequest{
		Email: "test@example.com",
	}

	body, _ := json.Marshal(requestBody)
	req := httptest.NewRequest("POST", "/api/scan", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response ScanResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if !response.Success {
		t.Errorf("Expected success=true, got error: %s", response.Error)
	}

	if response.Data == nil {
		t.Fatal("Expected scan data")
	}

	if response.Data.Domain != "example.com" {
		t.Errorf("Expected domain 'example.com', got %s", response.Data.Domain)
	}

	if len(response.Data.Results) == 0 {
		t.Error("Expected at least one scan result")
	}
}

func newTestIntelManager(t *testing.T, feedData string) (*intel.Manager, func()) {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, feedData)
	}))

	client := server.Client()
	client.Timeout = 5 * time.Second

	manager, err := intel.NewManager(
		intel.FeedConfig{
			Feeds: []intel.Feed{
				{
					Name: "test_feed",
					URL:  server.URL,
					Type: []string{"suspicious"},
				},
			},
		},
		intel.WithStorageDir(t.TempDir()),
		intel.WithHTTPClient(client),
		intel.WithLogger(log.New(io.Discard, "", 0)),
		intel.WithResolverTimeout(50*time.Millisecond),
		intel.WithDNSCacheTTL(100*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("failed to create test intel manager: %v", err)
	}

	cleanup := func() {
		server.Close()
	}

	return manager, cleanup
}
