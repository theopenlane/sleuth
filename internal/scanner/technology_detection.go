package scanner

import (
	"context"
	"fmt"
	"net"
	"net/http"

	"github.com/projectdiscovery/cdncheck"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"

	"github.com/theopenlane/sleuth/internal/types"
)

// performTechnologyDetection identifies technologies used by the domain
func (s *Scanner) performTechnologyDetection(ctx context.Context, domain string) *types.CheckResult {
	result := &types.CheckResult{
		CheckName: "technology_detection",
		Status:    "pass",
		Findings:  []types.Finding{},
		Metadata:  make(map[string]interface{}),
	}

	// This method focuses on DNS-based technology detection
	// HTTP-based detection is handled in performHTTPAnalysis

	// Use cdncheck library for comprehensive CDN, cloud provider, and WAF detection
	s.detectInfrastructure(ctx, domain, result)

	return result
}

// detectTechnologies identifies technologies from HTTP headers and body content
func (s *Scanner) detectTechnologies(body string, headers http.Header, result *types.CheckResult) {
	client, err := wappalyzer.New()
	if err != nil {
		result.Findings = append(result.Findings, types.Finding{
			Severity:    "info",
			Type:        "technology_error",
			Description: fmt.Sprintf("Technology fingerprinting failed: %v", err),
		})
		return
	}

	fingerprints := client.Fingerprint(headers, []byte(body))
	technologies := make([]string, 0, len(fingerprints))
	for tech := range fingerprints {
		technologies = append(technologies, tech)
		result.Findings = append(result.Findings, types.Finding{
			Severity:    "info",
			Type:        "technology",
			Description: fmt.Sprintf("Technology: %s", tech),
		})
	}
	result.Metadata["detected_technologies"] = technologies
}

// detectInfrastructure detects CDN, cloud provider, and WAF using cdncheck library
func (s *Scanner) detectInfrastructure(ctx context.Context, domain string, result *types.CheckResult) {
	// Initialize cdncheck client
	client := cdncheck.New()

	// Track what we've already reported to avoid duplicates
	seen := make(map[string]bool)

	// Use context-aware DNS resolver
	resolver := net.DefaultResolver

	// Check domain via CNAME
	if cname, err := resolver.LookupCNAME(ctx, domain); err == nil && cname != domain+"." {
		if matched, provider, itemType, checkErr := client.Check(net.ParseIP(cname)); matched && checkErr == nil && provider != "" {
			key := fmt.Sprintf("cname:%s:%s", provider, itemType)
			if !seen[key] {
				seen[key] = true
				result.Findings = append(result.Findings, types.Finding{
					Severity:    "info",
					Type:        "technology",
					Description: fmt.Sprintf("%s: %s", itemType, provider),
					Details:     fmt.Sprintf("CNAME points to %s", cname),
				})
			}
		}
	}

	// Check IPs for cloud provider and CDN detection
	if ips, err := resolver.LookupIP(ctx, "ip", domain); err == nil && len(ips) > 0 {
		for _, ip := range ips {
			// Check both IPv4 and IPv6
			matched, provider, itemType, checkErr := client.Check(ip)
			if checkErr == nil && matched && provider != "" {
				key := fmt.Sprintf("ip:%s:%s:%s", ip.String(), provider, itemType)
				if !seen[key] {
					seen[key] = true
					result.Findings = append(result.Findings, types.Finding{
						Severity:    "info",
						Type:        "technology",
						Description: fmt.Sprintf("%s: %s", itemType, provider),
						Details:     fmt.Sprintf("IP %s belongs to %s", ip.String(), provider),
					})
				}
			}
		}
	}
}
