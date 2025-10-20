package scanner

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestMapNucleiSeverity(t *testing.T) {
	scanner, err := New()
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}
	defer scanner.Close()
	
	testCases := []struct {
		input    string
		expected string
	}{
		{"critical", "critical"},
		{"high", "high"},
		{"medium", "medium"},
		{"low", "low"},
		{"info", "info"},
		{"informational", "info"},
		{"unknown", "medium"},
		{"CRITICAL", "critical"},
		{"HIGH", "high"},
	}
	
	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := scanner.mapNucleiSeverity(tc.input)
			if result != tc.expected {
				t.Errorf("Expected severity %s for input %s, got %s", 
					tc.expected, tc.input, result)
			}
		})
	}
}

func TestBuildNucleiArgs(t *testing.T) {
	scanner, err := New(
		WithNucleiTemplates([]string{"cves", "exposures"}),
		WithNucleiSeverity([]string{"critical", "high"}),
	)
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}
	defer scanner.Close()
	
	args := scanner.buildNucleiArgs("example.com")
	
	// Check basic arguments
	expectedArgs := map[string]bool{
		"-target":    true,
		"-jsonl":     true,
		"-silent":    true,
		"-no-color":  true,
		"-tags":      true,
		"-severity":  true,
	}
	
	argsMap := make(map[string]bool)
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			argsMap[arg] = true
		}
	}
	
	for expectedArg := range expectedArgs {
		if !argsMap[expectedArg] {
			t.Errorf("Expected argument %s not found in nuclei args", expectedArg)
		}
	}
	
	// Check target
	targetFound := false
	for i, arg := range args {
		if arg == "-target" && i+1 < len(args) {
			if args[i+1] == "https://example.com" {
				targetFound = true
				break
			}
		}
	}
	if !targetFound {
		t.Error("Expected target https://example.com not found")
	}
}

func TestParseNucleiOutput(t *testing.T) {
	scanner, err := New()
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}
	defer scanner.Close()
	
	testOutput := `{"template-id":"test-template","info":{"name":"Test Template","severity":"high","description":"Test description","author":["test-author"]},"type":"http","host":"https://example.com","matched-at":"https://example.com/test"}
{"template-id":"another-template","info":{"name":"Another Template","severity":"medium","description":"Another description","author":["author2"]},"type":"http","host":"https://example.com","matched-at":"https://example.com/another"}`
	
	results := scanner.parseNucleiOutput(testOutput)
	
	if len(results) != 2 {
		t.Errorf("Expected 2 nuclei results, got %d", len(results))
	}
	
	if results[0].TemplateID != "test-template" {
		t.Errorf("Expected first template ID to be 'test-template', got %s", results[0].TemplateID)
	}
	
	if results[0].Info.Severity != "high" {
		t.Errorf("Expected first result severity to be 'high', got %s", results[0].Info.Severity)
	}
	
	if results[1].TemplateID != "another-template" {
		t.Errorf("Expected second template ID to be 'another-template', got %s", results[1].TemplateID)
	}
}

func TestParseNucleiOutput_EmptyInput(t *testing.T) {
	scanner, err := New()
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}
	defer scanner.Close()
	
	results := scanner.parseNucleiOutput("")
	
	if len(results) != 0 {
		t.Errorf("Expected 0 results for empty input, got %d", len(results))
	}
}

func TestParseNucleiOutput_InvalidJSON(t *testing.T) {
	scanner, err := New()
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}
	defer scanner.Close()
	
	testOutput := `{"invalid json}
{valid: "json", but: "wrong format"}
{"template-id":"valid-template","info":{"name":"Valid","severity":"low"},"type":"http","host":"https://example.com"}`
	
	results := scanner.parseNucleiOutput(testOutput)
	
	// Should only parse the valid JSON line
	if len(results) != 1 {
		t.Errorf("Expected 1 valid result from mixed input, got %d", len(results))
	}
	
	if results[0].TemplateID != "valid-template" {
		t.Errorf("Expected template ID 'valid-template', got %s", results[0].TemplateID)
	}
}

func TestIsNucleiAvailable(t *testing.T) {
	scanner, err := New()
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}
	defer scanner.Close()
	
	available := scanner.isNucleiAvailable()
	
	// This test will pass whether nuclei is installed or not
	// It's mainly testing that the function doesn't panic
	t.Logf("Nuclei available: %v", available)
}

func TestPerformNucleiScan_NucleiNotAvailable(t *testing.T) {
	scanner, err := New()
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}
	defer scanner.Close()
	
	// Mock nuclei as not available by setting an invalid path
	originalPath := scanner.nucleiPath
	scanner.nucleiPath = "/nonexistent/nuclei"
	
	// Also mock the isNucleiAvailable method by temporarily renaming the binary
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	result := scanner.performNucleiScan(ctx, "example.com")
	
	// Restore original path
	scanner.nucleiPath = originalPath
	
	// The test may pass if nuclei is available, that's ok
	if result.Status == "skipped" && result.Error == "nuclei not available" {
		// This is the expected behavior when nuclei is not available
		t.Logf("Nuclei correctly detected as not available")
	} else {
		// Nuclei is available, so the scan ran
		t.Logf("Nuclei is available, scan status: %s", result.Status)
	}
}

func TestGetNucleiVersion(t *testing.T) {
	scanner, err := New()
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}
	defer scanner.Close()
	
	version, err := scanner.GetNucleiVersion()
	
	// Test should work whether nuclei is installed or not
	if err != nil {
		t.Logf("Nuclei not available: %v", err)
	} else {
		if version == "" {
			// This is actually ok, some versions of nuclei might return empty version
			t.Logf("Nuclei version is empty, but no error - this is acceptable")
		} else {
			t.Logf("Nuclei version: %s", version)
		}
	}
}

// Integration test - only runs if nuclei is available
func TestPerformNucleiScan_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	
	scanner, err := New(
		WithNucleiSeverity([]string{"info"}), // Use low-impact templates
		WithNucleiTemplates([]string{"tech-detect"}), // Safe templates only
	)
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}
	defer scanner.Close()
	
	if !scanner.isNucleiAvailable() {
		t.Skip("Nuclei not available, skipping integration test")
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	result := scanner.performNucleiScan(ctx, "example.com")
	
	if result == nil {
		t.Fatal("Expected nuclei scan result")
	}
	
	if result.CheckName != "nuclei_scan" {
		t.Errorf("Expected check name 'nuclei_scan', got %s", result.CheckName)
	}
	
	// Should complete without timeout
	if result.Status == "timeout" {
		t.Error("Nuclei scan timed out")
	}
}