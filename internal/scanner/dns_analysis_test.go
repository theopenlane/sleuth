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
