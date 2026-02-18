package scanner

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/projectdiscovery/cdncheck"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"

	"github.com/theopenlane/sleuth/internal/types"
)

// performTechnologyDetection identifies technologies used by the domain.
func (s *Scanner) performTechnologyDetection(ctx context.Context, domain string) *types.CheckResult {
	result := newCheckResult("technology_detection")
	s.detectInfrastructure(ctx, domain, result)
	return result
}

// detectTechnologies identifies technologies from HTTP headers and body content.
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

// detectInfrastructure detects CDN, cloud provider, and WAF using cdncheck.
func (s *Scanner) detectInfrastructure(ctx context.Context, domain string, result *types.CheckResult) {
	client := cdncheck.New()
	seen := make(map[string]bool)
	resolver := net.DefaultResolver

	dnsCtx, cancel := s.withDNSTimeout(ctx)
	defer cancel()

	if cname, err := resolver.LookupCNAME(dnsCtx, domain); err == nil && cname != domain+"." {
		cnameClean := strings.TrimSuffix(cname, ".")
		if matched, provider, itemType, checkErr := client.CheckSuffix(cnameClean); matched && checkErr == nil && provider != "" {
			key := fmt.Sprintf("cname:%s:%s", provider, itemType)
			if !seen[key] {
				seen[key] = true
				result.Findings = append(result.Findings, types.Finding{
					Severity:    "info",
					Type:        "technology",
					Description: fmt.Sprintf("%s: %s", itemType, provider),
					Details:     fmt.Sprintf("CNAME points to %s", cnameClean),
				})
			}
		}
	}

	if ips, err := resolver.LookupIP(dnsCtx, "ip", domain); err == nil && len(ips) > 0 {
		for _, ip := range ips {
			matched, provider, itemType, checkErr := client.Check(ip)
			if checkErr == nil && matched && provider != "" {
				key := fmt.Sprintf("ip:%s:%s:%s", ip.String(), provider, itemType)
				if seen[key] {
					continue
				}

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
