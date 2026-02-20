package cloudflare

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAnalyzeCompliancePage_Success(t *testing.T) {
	expected := CompliancePage{
		PageType:      "trust_center",
		Title:         "Trust Center",
		Summary:       "Acme Corp maintains SOC 2 Type II and ISO 27001 certifications.",
		Frameworks:    []string{"SOC 2 Type II", "ISO 27001"},
		LastUpdated:   "January 2026",
		DownloadLinks: []string{"https://acme.com/reports/soc2-2025.pdf"},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}

		var reqBody browserRenderingRequest
		if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}

		if reqBody.URL != "https://acme.com/trust" {
			t.Errorf("expected URL https://acme.com/trust, got %s", reqBody.URL)
		}

		if reqBody.GotoOptions == nil {
			t.Fatal("expected gotoOptions to be set for SPA rendering")
		}

		if reqBody.GotoOptions.WaitUntil != "networkidle2" {
			t.Errorf("expected gotoOptions.waitUntil=networkidle2, got %s", reqBody.GotoOptions.WaitUntil)
		}

		if reqBody.GotoOptions.Timeout != browserNavigationTimeout {
			t.Errorf("expected gotoOptions.timeout=%d, got %d", browserNavigationTimeout, reqBody.GotoOptions.Timeout)
		}

		w.Header().Set("Content-Type", "application/json")

		if err := json.NewEncoder(w).Encode(compliancePageResponse{
			Success: true,
			Result:  expected,
		}); err != nil {
			t.Fatalf("failed to encode response: %v", err)
		}
	}))
	defer server.Close()

	client, err := New("test-account", "test-token",
		WithHTTPClient(server.Client()),
		WithBaseURL(server.URL),
	)
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	result, err := client.AnalyzeCompliancePage(context.Background(), "https://acme.com/trust")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.URL != "https://acme.com/trust" {
		t.Errorf("expected URL https://acme.com/trust, got %s", result.URL)
	}

	if result.PageType != expected.PageType {
		t.Errorf("expected page type %s, got %s", expected.PageType, result.PageType)
	}

	if result.Title != expected.Title {
		t.Errorf("expected title %s, got %s", expected.Title, result.Title)
	}

	if len(result.Frameworks) != len(expected.Frameworks) {
		t.Fatalf("expected %d frameworks, got %d", len(expected.Frameworks), len(result.Frameworks))
	}

	for i, f := range expected.Frameworks {
		if result.Frameworks[i] != f {
			t.Errorf("framework %d: expected %s, got %s", i, f, result.Frameworks[i])
		}
	}

	if len(result.DownloadLinks) != len(expected.DownloadLinks) {
		t.Fatalf("expected %d download links, got %d", len(expected.DownloadLinks), len(result.DownloadLinks))
	}
}

func TestAnalyzeCompliancePage_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	client, err := New("test-account", "test-token",
		WithHTTPClient(server.Client()),
		WithBaseURL(server.URL),
	)
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}

	_, err = client.AnalyzeCompliancePage(context.Background(), "https://example.com/trust")
	if err == nil {
		t.Fatal("expected error for API error response")
	}
}

func TestBuildCompliancePageSchema(t *testing.T) {
	schema := buildCompliancePageSchema()

	if schema.JSONSchema.Name != compliancePageSchemaName {
		t.Errorf("expected schema name %s, got %s", compliancePageSchemaName, schema.JSONSchema.Name)
	}

	props := schema.JSONSchema.Schema.Properties
	expectedFields := []string{"page_type", "title", "summary", "frameworks", "last_updated", "download_links", "subprocessors", "compliance_links"}

	for _, field := range expectedFields {
		if _, ok := props[field]; !ok {
			t.Errorf("expected field %s in schema properties", field)
		}
	}
}
