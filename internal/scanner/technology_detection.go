package scanner

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"

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

	// Check for CDN via DNS
	s.detectCDNFromDNS(domain, result)

	// Check for hosting provider via IP ranges
	s.detectHostingProvider(domain, result)

	// Check for cloud services
	s.detectCloudServices(domain, result)

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

// detectCDNFromDNS detects CDN usage from DNS records
func (s *Scanner) detectCDNFromDNS(domain string, result *types.CheckResult) {
	// Check CNAME records for CDN patterns
	if cname, err := net.LookupCNAME(domain); err == nil && cname != domain+"." {
		cnameClean := strings.TrimSuffix(cname, ".")

		cdnPatterns := map[string]string{
			"cloudfront.net":        "Amazon CloudFront",
			"cloudflare.com":        "Cloudflare",
			"fastly.com":            "Fastly",
			"akamai.net":            "Akamai",
			"azureedge.net":         "Azure CDN",
			"googleusercontent.com": "Google Cloud CDN",
			"jsdelivr.net":          "jsDelivr CDN",
			"maxcdn.com":            "MaxCDN",
		}

		for pattern, cdn := range cdnPatterns {
			if strings.Contains(strings.ToLower(cnameClean), pattern) {
				result.Findings = append(result.Findings, types.Finding{
					Severity:    "info",
					Type:        "technology",
					Description: fmt.Sprintf("CDN: %s", cdn),
					Details:     fmt.Sprintf("CNAME points to %s", cnameClean),
				})
			}
		}
	}
}

// detectHostingProvider detects hosting provider from IP ranges
func (s *Scanner) detectHostingProvider(domain string, result *types.CheckResult) {
	if ips, err := net.LookupIP(domain); err == nil && len(ips) > 0 {
		for _, ip := range ips {
			if ip.To4() == nil {
				continue // Skip IPv6 for now
			}
			ipStr := ip.String()

			// AWS IP ranges (simplified)
			awsPrefixes := []string{
				"52.", "54.", "18.", "35.", "13.", "34.", "3.", "15.",
				"16.", "17.", "23.", "50.", "52.", "75.", "99.",
			}

			// Google Cloud IP ranges (simplified)
			gcpPrefixes := []string{
				"35.", "34.", "104.", "130.", "146.", "172.", "173.",
			}

			// Azure IP ranges (simplified)
			azurePrefixes := []string{
				"13.", "20.", "23.", "40.", "51.", "52.", "65.", "104.",
				"137.", "138.", "168.",
			}

			for _, prefix := range awsPrefixes {
				if strings.HasPrefix(ipStr, prefix) {
					result.Findings = append(result.Findings, types.Finding{
						Severity:    "info",
						Type:        "technology",
						Description: "Hosting: Amazon Web Services",
						Details:     fmt.Sprintf("IP: %s", ipStr),
					})
					return
				}
			}

			for _, prefix := range gcpPrefixes {
				if strings.HasPrefix(ipStr, prefix) {
					result.Findings = append(result.Findings, types.Finding{
						Severity:    "info",
						Type:        "technology",
						Description: "Hosting: Google Cloud Platform",
						Details:     fmt.Sprintf("IP: %s", ipStr),
					})
					return
				}
			}

			for _, prefix := range azurePrefixes {
				if strings.HasPrefix(ipStr, prefix) {
					result.Findings = append(result.Findings, types.Finding{
						Severity:    "info",
						Type:        "technology",
						Description: "Hosting: Microsoft Azure",
						Details:     fmt.Sprintf("IP: %s", ipStr),
					})
					return
				}
			}
		}
	}
}

// detectCloudServices detects cloud services from DNS patterns
func (s *Scanner) detectCloudServices(domain string, result *types.CheckResult) {
	// Check for common cloud service patterns in CNAME records
	if cname, err := net.LookupCNAME(domain); err == nil && cname != domain+"." {
		cnameClean := strings.TrimSuffix(cname, ".")

		cloudPatterns := map[string]string{
			"amazonaws.com":         "Amazon Web Services",
			"googleusercontent.com": "Google Cloud",
			"azurewebsites.net":     "Azure App Service",
			"herokuapp.com":         "Heroku",
			"netlify.com":           "Netlify",
			"vercel.com":            "Vercel",
			"github.io":             "GitHub Pages",
			"gitlab.io":             "GitLab Pages",
		}

		for pattern, service := range cloudPatterns {
			if strings.Contains(strings.ToLower(cnameClean), pattern) {
				result.Findings = append(result.Findings, types.Finding{
					Severity:    "info",
					Type:        "technology",
					Description: fmt.Sprintf("Cloud Service: %s", service),
					Details:     fmt.Sprintf("CNAME points to %s", cnameClean),
				})
			}
		}
	}
}
