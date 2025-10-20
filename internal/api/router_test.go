package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/theopenlane/sleuth/internal/scanner"
)

func TestNewRouter(t *testing.T) {
	mockScanner := NewMockScanner(false, 0)
	router := NewRouter(mockScanner, nil, 1024, 60*time.Second)

	if router == nil {
		t.Fatal("Expected router to be created")
	}
}

func TestSwaggerEndpoint(t *testing.T) {
	mockScanner := NewMockScanner(false, 0)
	handler := NewRouter(mockScanner, nil, 1024, 60*time.Second)

	req := httptest.NewRequest("GET", "/swagger/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Should return a redirect or swagger UI page
	if w.Code != http.StatusOK && w.Code != http.StatusFound && w.Code != http.StatusMovedPermanently {
		t.Errorf("Expected status 200, 301, or 302 for swagger endpoint, got %d", w.Code)
	}
}

func TestRootRedirect(t *testing.T) {
	mockScanner := NewMockScanner(false, 0)
	handler := NewRouter(mockScanner, nil, 1024, 60*time.Second)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Errorf("Expected status 302 for root redirect, got %d", w.Code)
	}

	location := w.Header().Get("Location")
	if location != "/ui" {
		t.Errorf("Expected redirect to /ui, got %s", location)
	}
}

func TestPingEndpoint(t *testing.T) {
	mockScanner := NewMockScanner(false, 0)
	handler := NewRouter(mockScanner, nil, 1024, 60*time.Second)

	req := httptest.NewRequest("GET", "/ping", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 for ping endpoint, got %d", w.Code)
	}

	if w.Body.String() != "." {
		t.Errorf("Expected ping response '.', got %s", w.Body.String())
	}
}

func TestCORSHeaders(t *testing.T) {
	mockScanner := NewMockScanner(false, 0)
	handler := NewRouter(mockScanner, nil, 1024, 60*time.Second)

	req := httptest.NewRequest("OPTIONS", "/api/health", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 for OPTIONS request, got %d", w.Code)
	}

	corsOrigin := w.Header().Get("Access-Control-Allow-Origin")
	if corsOrigin != "*" {
		t.Errorf("Expected CORS origin '*', got %s", corsOrigin)
	}

	corsMethods := w.Header().Get("Access-Control-Allow-Methods")
	if !contains(corsMethods, "POST") {
		t.Errorf("Expected CORS methods to include POST, got %s", corsMethods)
	}
}

func TestIntegrationWithRealScanner(t *testing.T) {
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

	// Test that all endpoints are accessible
	endpoints := []struct {
		method string
		path   string
		status int
	}{
		{"GET", "/ping", 200},
		{"GET", "/api/health", 200},
		{"GET", "/swagger/", 301}, // Swagger redirects
		{"GET", "/", 302},          // Redirect to UI
	}

	for _, endpoint := range endpoints {
		req := httptest.NewRequest(endpoint.method, endpoint.path, nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != endpoint.status {
			t.Errorf("Expected status %d for %s %s, got %d",
				endpoint.status, endpoint.method, endpoint.path, w.Code)
		}
	}
}

// Helper function for string contains check
func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		(findInString(s, substr))
}

func findInString(s, pattern string) bool {
	for i := 0; i <= len(s)-len(pattern); i++ {
		if s[i:i+len(pattern)] == pattern {
			return true
		}
	}
	return false
}
