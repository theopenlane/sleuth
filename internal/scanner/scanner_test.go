package scanner

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	scanner, err := New()
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}
	defer scanner.Close()
	
	if scanner.options == nil {
		t.Error("Expected scanner to have options")
	}
}

func TestNewWithOptions(t *testing.T) {
	scanner, err := New(
		WithVerbose(true),
		WithMaxSubdomains(25),
		WithDNSTimeout(5*time.Second),
	)
	if err != nil {
		t.Fatalf("Failed to create scanner with options: %v", err)
	}
	defer scanner.Close()
	
	if !scanner.options.Verbose {
		t.Error("Expected verbose mode to be enabled")
	}
	
	if scanner.options.MaxSubdomains != 25 {
		t.Errorf("Expected max subdomains to be 25, got %d", scanner.options.MaxSubdomains)
	}
	
	if scanner.options.DNSTimeout != 5*time.Second {
		t.Errorf("Expected DNS timeout to be 5s, got %v", scanner.options.DNSTimeout)
	}
}

func TestScanDomain_InvalidDomain(t *testing.T) {
	scanner, err := New()
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}
	defer scanner.Close()
	
	ctx := context.Background()
	
	// Test invalid domain
	_, err = scanner.ScanDomain(ctx, "invalid-domain")
	if err == nil {
		t.Error("Expected error for invalid domain")
	}
	
	if !strings.Contains(err.Error(), "invalid domain") {
		t.Errorf("Expected 'invalid domain' error, got: %v", err)
	}
}

func TestScanDomain_ValidDomain(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	
	scanner, err := New(
		WithMaxSubdomains(5), // Limit for testing
		WithNucleiTemplates([]string{}), // Disable nuclei for testing
	)
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}
	defer scanner.Close()
	
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	// Test with a well-known domain
	result, err := scanner.ScanDomain(ctx, "example.com")
	if err != nil {
		t.Fatalf("Failed to scan domain: %v", err)
	}
	
	if result.Domain != "example.com" {
		t.Errorf("Expected domain to be 'example.com', got %s", result.Domain)
	}
	
	if result.DomainInfo == nil {
		t.Error("Expected domain info to be populated")
	}
	
	if len(result.Results) == 0 {
		t.Error("Expected at least one scan result")
	}
	
	// Check for expected result types
	resultTypes := make(map[string]bool)
	for _, checkResult := range result.Results {
		resultTypes[checkResult.CheckName] = true
	}
	
	expectedTypes := []string{"dns_analysis", "subdomain_discovery", "http_analysis", "technology_detection"}
	for _, expectedType := range expectedTypes {
		if !resultTypes[expectedType] {
			t.Errorf("Expected result type '%s' not found", expectedType)
		}
	}
}

func TestScanDomain_EmailInput(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	
	scanner, err := New(
		WithMaxSubdomains(5),
		WithNucleiTemplates([]string{}),
	)
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}
	defer scanner.Close()
	
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	// Test with email that should extract domain
	result, err := scanner.ScanDomain(ctx, "test@example.com")
	if err != nil {
		t.Fatalf("Failed to scan email domain: %v", err)
	}
	
	if result.Domain != "example.com" {
		t.Errorf("Expected domain to be 'example.com', got %s", result.Domain)
	}
}

func TestClose(t *testing.T) {
	scanner, err := New()
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}
	
	err = scanner.Close()
	if err != nil {
		t.Errorf("Failed to close scanner: %v", err)
	}
}

// Benchmark tests
func BenchmarkScanDomain(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping benchmark in short mode")
	}
	
	scanner, err := New(
		WithMaxSubdomains(10),
		WithNucleiTemplates([]string{}), // Disable nuclei for benchmarking
	)
	if err != nil {
		b.Fatalf("Failed to create scanner: %v", err)
	}
	defer scanner.Close()
	
	ctx := context.Background()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := scanner.ScanDomain(ctx, "example.com")
		if err != nil {
			b.Fatalf("Scan failed: %v", err)
		}
	}
}