package scanner

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/theopenlane/sleuth/internal/types"
)

func TestTakeoverFingerprintForCNAME(t *testing.T) {
	scanner, err := New()
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}
	defer func() { _ = scanner.Close() }()

	testCases := []struct {
		cname      string
		vulnerable bool
	}{
		{"test.herokuapp.com", true},
		{"example.azurewebsites.net", true},
		{"test.github.io", true},
		{"test.s3.amazonaws.com", true},
		{"normal-site.com", false},
		{"google.com", false},
		{"example.com", false},
		{"test.fastly.net", true},
		{"app.zendesk.com", true},
	}

	for _, tc := range testCases {
		t.Run(tc.cname, func(t *testing.T) {
			_, result := scanner.takeoverFingerprintForCNAME(tc.cname)
			if result != tc.vulnerable {
				t.Errorf("Expected %s to be vulnerable: %v, got: %v",
					tc.cname, tc.vulnerable, result)
			}
		})
	}
}

func TestAnalyzeEmailProvider(t *testing.T) {
	scanner, err := New()
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}
	defer func() { _ = scanner.Close() }()

	testCases := []struct {
		mxRecords []string
		expected  string
	}{
		{[]string{"aspmx.l.google.com"}, "Google Workspace"},
		{[]string{"outlook.com"}, "Microsoft 365"},
		{[]string{"mail.protection.outlook.com"}, "Microsoft 365"},
		{[]string{"pphosted.com"}, "Proofpoint"},
		{[]string{"unknown-provider.com"}, ""},
	}

	for _, tc := range testCases {
		t.Run(tc.mxRecords[0], func(t *testing.T) {
			result := &types.CheckResult{
				CheckName: "test",
				Status:    "pass",
				Findings:  []types.Finding{},
				Metadata:  make(map[string]any),
			}

			scanner.analyzeEmailProvider(tc.mxRecords, result)

			if tc.expected == "" {
				if len(result.Findings) > 0 {
					t.Errorf("Expected no findings for %s, got %d", tc.mxRecords[0], len(result.Findings))
				}
			} else {
				found := false
				for _, finding := range result.Findings {
					if finding.Type == "email_provider" &&
						strings.Contains(finding.Description, tc.expected) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected to find provider %s for %s", tc.expected, tc.mxRecords[0])
				}
			}
		})
	}
}

func TestAnalyzeTXTRecords(t *testing.T) {
	scanner, err := New()
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}
	defer func() { _ = scanner.Close() }()

	testCases := []struct {
		name         string
		txtRecords   []string
		expectedType string
		severity     string
	}{
		{
			name:         "weak SPF +all",
			txtRecords:   []string{"v=spf1 +all"},
			expectedType: "weak_spf",
			severity:     "high",
		},
		{
			name:         "neutral SPF ?all",
			txtRecords:   []string{"v=spf1 ?all"},
			expectedType: "weak_spf",
			severity:     "medium",
		},
		{
			name:         "good SPF",
			txtRecords:   []string{"v=spf1 include:_spf.google.com ~all"},
			expectedType: "",
			severity:     "",
		},
		{
			name:         "no SPF",
			txtRecords:   []string{"some-other-record=value"},
			expectedType: "missing_spf",
			severity:     "medium",
		},
		{
			name:         "domain verification",
			txtRecords:   []string{"google-site-verification=abc123"},
			expectedType: "domain_verification",
			severity:     "info",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := &types.CheckResult{
				CheckName: "test",
				Status:    "pass",
				Findings:  []types.Finding{},
				Metadata:  make(map[string]any),
			}

			scanner.analyzeTXTRecords(tc.txtRecords, result)

			if tc.expectedType == "" {
				return // No specific finding expected
			}

			found := false
			for _, finding := range result.Findings {
				if finding.Type == tc.expectedType && finding.Severity == tc.severity {
					found = true
					break
				}
			}

			if !found {
				t.Errorf("Expected finding of type %s with severity %s not found. Got %d findings",
					tc.expectedType, tc.severity, len(result.Findings))
				for i, finding := range result.Findings {
					t.Logf("Finding %d: Type=%s, Severity=%s", i, finding.Type, finding.Severity)
				}
			}
		})
	}
}

func TestDetectVerificationServices_KnownService(t *testing.T) {
	scanner, err := New()
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}
	defer func() { _ = scanner.Close() }()

	result := &types.CheckResult{
		CheckName: "test",
		Status:    "pass",
		Findings:  []types.Finding{},
		Metadata:  make(map[string]any),
	}

	scanner.detectVerificationServices("slack-domain-verification=h8reqklcuarkqhtwmvxh2rjgewy9yqw5cykpz1nwk", "slack-domain-verification=h8ReQlCUaRkqhTWmVxH2rJgeWy9yQW5CyKPz1NWk", result)

	var hasDomainVerification, hasServiceDetection bool
	for _, f := range result.Findings {
		if f.Type == "domain_verification" {
			hasDomainVerification = true
		}
		if f.Type == "service_detection" && strings.Contains(f.Description, "Slack") {
			hasServiceDetection = true
		}
	}

	if !hasDomainVerification {
		t.Error("expected domain_verification finding for slack record")
	}
	if !hasServiceDetection {
		t.Error("expected service_detection finding for Slack")
	}
}

func TestDetectVerificationServices_MultipleServices(t *testing.T) {
	scanner, err := New()
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}
	defer func() { _ = scanner.Close() }()

	result := &types.CheckResult{
		CheckName: "test",
		Status:    "pass",
		Findings:  []types.Finding{},
		Metadata:  make(map[string]any),
	}

	txtRecords := []string{
		"v=spf1 include:_spf.google.com ~all",
		"slack-domain-verification=abc123",
		"hubspot-domain-verification=xyz789",
		"google-site-verification=ggg111",
	}

	scanner.analyzeTXTRecords(txtRecords, result)

	services, _ := result.Metadata["detected_services"].([]string)
	if len(services) != 3 {
		t.Fatalf("expected 3 detected services, got %d: %v", len(services), services)
	}

	// Services should be sorted
	expected := []string{"Google Workspace", "HubSpot", "Slack"}
	for i, svc := range expected {
		if services[i] != svc {
			t.Errorf("expected services[%d] = %q, got %q", i, svc, services[i])
		}
	}

	// Count service_detection findings (should be 3, one per unique service)
	var serviceDetections int
	for _, f := range result.Findings {
		if f.Type == "service_detection" {
			serviceDetections++
		}
	}
	if serviceDetections != 3 {
		t.Errorf("expected 3 service_detection findings, got %d", serviceDetections)
	}
}

func TestDetectVerificationServices_UnknownVerification(t *testing.T) {
	scanner, err := New()
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}
	defer func() { _ = scanner.Close() }()

	result := &types.CheckResult{
		CheckName: "test",
		Status:    "pass",
		Findings:  []types.Finding{},
		Metadata:  make(map[string]any),
	}

	scanner.detectVerificationServices("custom-verification=abc123", "custom-verification=abc123", result)

	var hasDomainVerification, hasServiceDetection bool
	for _, f := range result.Findings {
		if f.Type == "domain_verification" {
			hasDomainVerification = true
		}
		if f.Type == "service_detection" {
			hasServiceDetection = true
		}
	}

	if !hasDomainVerification {
		t.Error("expected domain_verification finding for generic verification record")
	}
	if hasServiceDetection {
		t.Error("unexpected service_detection finding for unknown verification record")
	}
}

func TestDetectVerificationServices_ColonSeparator(t *testing.T) {
	scanner, err := New()
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}
	defer func() { _ = scanner.Close() }()

	result := &types.CheckResult{
		CheckName: "test",
		Status:    "pass",
		Findings:  []types.Finding{},
		Metadata:  make(map[string]any),
	}

	scanner.detectVerificationServices("brevo-code:abc123", "brevo-code:abc123", result)

	var hasServiceDetection bool
	for _, f := range result.Findings {
		if f.Type == "service_detection" && strings.Contains(f.Description, "Brevo") {
			hasServiceDetection = true
		}
	}

	if !hasServiceDetection {
		t.Error("expected service_detection finding for brevo-code with colon separator")
	}
}

func TestFinalizeDetectedServices_CleansUpInternalMetadata(t *testing.T) {
	scanner, err := New()
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}
	defer func() { _ = scanner.Close() }()

	result := &types.CheckResult{
		CheckName: "test",
		Status:    "pass",
		Findings:  []types.Finding{},
		Metadata:  make(map[string]any),
	}

	// Simulate service detection populating _service_set
	serviceSet := map[string]struct{}{
		"Slack":  {},
		"HubSpot": {},
	}
	result.Metadata["_service_set"] = serviceSet

	scanner.finalizeDetectedServices(result)

	if _, exists := result.Metadata["_service_set"]; exists {
		t.Error("expected _service_set to be removed after finalization")
	}

	services, ok := result.Metadata["detected_services"].([]string)
	if !ok {
		t.Fatal("expected detected_services in metadata")
	}
	if len(services) != 2 {
		t.Fatalf("expected 2 services, got %d", len(services))
	}
	if services[0] != "HubSpot" || services[1] != "Slack" {
		t.Errorf("expected sorted [HubSpot, Slack], got %v", services)
	}
}

func TestDetectVerificationServices_DedupSameService(t *testing.T) {
	scanner, err := New()
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}
	defer func() { _ = scanner.Close() }()

	result := &types.CheckResult{
		CheckName: "test",
		Status:    "pass",
		Findings:  []types.Finding{},
		Metadata:  make(map[string]any),
	}

	// Two google records should produce only one service_detection
	txtRecords := []string{
		"v=spf1 ~all",
		"google-site-verification=abc",
		"google-site-verification=def",
	}

	scanner.analyzeTXTRecords(txtRecords, result)

	var serviceDetections int
	for _, f := range result.Findings {
		if f.Type == "service_detection" && strings.Contains(f.Description, "Google Workspace") {
			serviceDetections++
		}
	}
	if serviceDetections != 1 {
		t.Errorf("expected 1 deduped service_detection for Google Workspace, got %d", serviceDetections)
	}

	services, _ := result.Metadata["detected_services"].([]string)
	if len(services) != 1 || services[0] != "Google Workspace" {
		t.Errorf("expected [Google Workspace], got %v", services)
	}
}

func TestPerformDNSAnalysis_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	scanner, err := New()
	if err != nil {
		t.Fatalf("Failed to create scanner: %v", err)
	}
	defer func() { _ = scanner.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result := scanner.performDNSAnalysis(ctx, "example.com")

	if result == nil {
		t.Fatal("Expected DNS analysis result")
	}

	if result.CheckName != "dns_analysis" {
		t.Errorf("Expected check name 'dns_analysis', got %s", result.CheckName)
	}

	// Should have some DNS records
	if result.Metadata["dns_records"] == nil {
		t.Error("Expected DNS records in metadata")
	}

	// example.com should have A records
	if result.Metadata["a_records"] == nil {
		t.Error("Expected A records for example.com")
	}
}
