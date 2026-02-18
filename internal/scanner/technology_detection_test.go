package scanner

import (
	"context"
	"net"
	"testing"

	"github.com/theopenlane/sleuth/internal/types"
)

func TestPerformTechnologyDetection(t *testing.T) {
	tests := []struct {
		name         string
		domain       string
		wantStatus   types.CheckStatus
		wantFindings bool
	}{
		{
			name:         "valid domain with infrastructure",
			domain:       "cloudflare.com",
			wantStatus:   types.CheckStatusPass,
			wantFindings: true,
		},
		{
			name:         "invalid domain",
			domain:       "invalid.domain.that.does.not.exist.example.invalid",
			wantStatus:   types.CheckStatusPass,
			wantFindings: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			result := scanner.performTechnologyDetection(context.Background(), tt.domain)

			if result.Status != tt.wantStatus {
				t.Errorf("performTechnologyDetection() status = %v, want %v", result.Status, tt.wantStatus)
			}

			hasFindings := len(result.Findings) > 0
			if hasFindings != tt.wantFindings {
				t.Errorf("performTechnologyDetection() hasFindings = %v, want %v", hasFindings, tt.wantFindings)
			}
		})
	}
}

func TestDetectInfrastructure(t *testing.T) {
	tests := []struct {
		name         string
		domain       string
		wantFindings bool
	}{
		{
			name:         "cloudflare domain",
			domain:       "cloudflare.com",
			wantFindings: true,
		},
		{
			name:         "amazon domain",
			domain:       "amazon.com",
			wantFindings: true,
		},
		{
			name:         "nonexistent domain",
			domain:       "nonexistent.invalid.domain.example",
			wantFindings: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner, err := New()
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			result := &types.CheckResult{
				Findings: []types.Finding{},
				Metadata: make(map[string]any),
			}

			scanner.detectInfrastructure(context.Background(), tt.domain, result)

			hasFindings := len(result.Findings) > 0
			if hasFindings != tt.wantFindings {
				t.Logf("Findings: %+v", result.Findings)
				t.Errorf("detectInfrastructure() hasFindings = %v, want %v", hasFindings, tt.wantFindings)
			}
		})
	}
}

func TestDetectInfrastructureNoDuplicates(t *testing.T) {
	scanner, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	result := &types.CheckResult{
		Findings: []types.Finding{},
		Metadata: make(map[string]any),
	}

	scanner.detectInfrastructure(context.Background(), "cloudflare.com", result)

	// Check that we don't have duplicate findings
	seen := make(map[string]bool)
	for _, finding := range result.Findings {
		key := finding.Description + "|" + finding.Details
		if seen[key] {
			t.Errorf("detectInfrastructure() produced duplicate finding: %s - %s", finding.Description, finding.Details)
		}
		seen[key] = true
	}
}

func TestDetectInfrastructureIPv6Support(t *testing.T) {
	scanner, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Test with a domain that has both IPv4 and IPv6
	result := &types.CheckResult{
		Findings: []types.Finding{},
		Metadata: make(map[string]any),
	}

	// Use google.com as it typically has both IPv4 and IPv6
	ips, lookupErr := net.LookupIP("google.com")
	if lookupErr != nil {
		t.Skip("Unable to resolve google.com for IPv6 test")
	}

	hasIPv6 := false
	for _, ip := range ips {
		if ip.To4() == nil {
			hasIPv6 = true
			break
		}
	}

	if !hasIPv6 {
		t.Skip("google.com does not have IPv6 addresses in this environment")
	}

	scanner.detectInfrastructure(context.Background(), "google.com", result)

	// Should have findings (likely Google Cloud)
	if len(result.Findings) == 0 {
		t.Error("detectInfrastructure() should detect infrastructure for google.com")
	}
}
