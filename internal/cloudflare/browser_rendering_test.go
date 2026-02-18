package cloudflare

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRenderCompanyProfile_Success(t *testing.T) {
	expected := CompanyProfile{
		Name:          "Acme Corp",
		Description:   "Acme Corp builds widgets for enterprise customers.",
		Industry:      "Technology",
		Products:      []string{"Widget Pro", "Widget Lite"},
		Location:      "San Francisco, CA",
		EmployeeRange: "51-200",
		WebsiteTitle:  "Acme Corp - Enterprise Widgets",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}

		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-token" {
			t.Errorf("expected Bearer test-token, got %s", auth)
		}

		var reqBody browserRenderingRequest
		if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}

		if reqBody.URL != "https://acme.com" {
			t.Errorf("expected URL https://acme.com, got %s", reqBody.URL)
		}

		if reqBody.ResponseFormat.Type != "json_schema" {
			t.Errorf("expected response format type json_schema, got %s", reqBody.ResponseFormat.Type)
		}

		w.Header().Set("Content-Type", "application/json")

		if err := json.NewEncoder(w).Encode(browserRenderingResponse{
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

	result, err := client.RenderCompanyProfile(context.Background(), "acme.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Name != expected.Name {
		t.Errorf("expected name %s, got %s", expected.Name, result.Name)
	}

	if result.Description != expected.Description {
		t.Errorf("expected description %s, got %s", expected.Description, result.Description)
	}

	if result.Industry != expected.Industry {
		t.Errorf("expected industry %s, got %s", expected.Industry, result.Industry)
	}

	if len(result.Products) != len(expected.Products) {
		t.Fatalf("expected %d products, got %d", len(expected.Products), len(result.Products))
	}

	for i, p := range expected.Products {
		if result.Products[i] != p {
			t.Errorf("product %d: expected %s, got %s", i, p, result.Products[i])
		}
	}

	if result.Location != expected.Location {
		t.Errorf("expected location %s, got %s", expected.Location, result.Location)
	}

	if result.EmployeeRange != expected.EmployeeRange {
		t.Errorf("expected employee range %s, got %s", expected.EmployeeRange, result.EmployeeRange)
	}

	if result.WebsiteTitle != expected.WebsiteTitle {
		t.Errorf("expected website title %s, got %s", expected.WebsiteTitle, result.WebsiteTitle)
	}
}

func TestRenderCompanyProfile_APIError(t *testing.T) {
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

	_, err = client.RenderCompanyProfile(context.Background(), "example.com")
	if err == nil {
		t.Fatal("expected error for API error response")
	}
}

func TestRenderCompanyProfile_RenderingFailed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if err := json.NewEncoder(w).Encode(browserRenderingResponse{
			Success: false,
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

	_, err = client.RenderCompanyProfile(context.Background(), "example.com")
	if err == nil {
		t.Fatal("expected error for rendering failure")
	}

	if err != ErrRenderingFailed {
		t.Errorf("expected ErrRenderingFailed, got %v", err)
	}
}

func TestBuildCompanyProfileSchema(t *testing.T) {
	schema := buildCompanyProfileSchema()

	if schema.Type != "json_schema" {
		t.Errorf("expected type json_schema, got %s", schema.Type)
	}

	if schema.JSONSchema.Name != schemaName {
		t.Errorf("expected schema name %s, got %s", schemaName, schema.JSONSchema.Name)
	}

	props := schema.JSONSchema.Schema.Properties
	expectedFields := []string{"name", "description", "industry", "products", "location", "employee_range", "website_title"}

	for _, field := range expectedFields {
		if _, ok := props[field]; !ok {
			t.Errorf("expected field %s in schema properties", field)
		}
	}

	if props["products"].Type != "array" {
		t.Errorf("expected products type array, got %s", props["products"].Type)
	}

	if props["products"].Items == nil {
		t.Fatal("expected products items to be defined")
	}
}
