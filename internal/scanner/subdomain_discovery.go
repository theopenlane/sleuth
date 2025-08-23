package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/theopenlane/sleuth/internal/types"
)

// performSubdomainDiscovery performs basic subdomain discovery using common patterns
func (s *Scanner) performSubdomainDiscovery(ctx context.Context, domain string) *types.CheckResult {
	result := &types.CheckResult{
		CheckName: "subdomain_discovery",
		Status:    "pass",
		Findings:  []types.Finding{},
		Metadata:  make(map[string]interface{}),
	}

	// Common subdomains to check
	commonSubdomains := []string{
		"www", "mail", "ftp", "admin", "api", "blog", "dev", "test", "staging", 
		"demo", "app", "mobile", "m", "portal", "secure", "shop", "store", 
		"support", "help", "docs", "cdn", "static", "assets", "img", "images",
		"vpn", "remote", "proxy", "gateway", "ns1", "ns2", "mx", "exchange",
		"owa", "webmail", "cpanel", "phpmyadmin", "mysql", "db", "database",
		"git", "svn", "jenkins", "ci", "build", "monitoring", "grafana",
		"kibana", "elastic", "prometheus", "metrics", "logs", "status",
	}

	var discoveredSubdomains []string
	var interesting []string

	limit := s.options.MaxSubdomains
	if limit > len(commonSubdomains) {
		limit = len(commonSubdomains)
	}

	// Check each subdomain
	for i, subdomain := range commonSubdomains {
		if i >= limit {
			break
		}

		select {
		case <-ctx.Done():
			break
		default:
		}

		fullDomain := fmt.Sprintf("%s.%s", subdomain, domain)
		
		// Try to resolve the subdomain
		if _, err := net.LookupHost(fullDomain); err == nil {
			discoveredSubdomains = append(discoveredSubdomains, fullDomain)
			
			// Check if it's interesting
			if s.isInterestingSubdomain(subdomain) {
				interesting = append(interesting, fullDomain)
				
				result.Findings = append(result.Findings, types.Finding{
					Severity:    "info",
					Type:        "interesting_subdomain",
					Description: fmt.Sprintf("Interesting subdomain discovered: %s", fullDomain),
					Details:     s.getSubdomainContext(subdomain),
				})
			}
		}
	}

	result.Metadata["total_subdomains"] = len(discoveredSubdomains)
	result.Metadata["subdomains"] = discoveredSubdomains
	result.Metadata["interesting_subdomains"] = interesting

	// Add summary finding
	if len(discoveredSubdomains) > 0 {
		result.Findings = append(result.Findings, types.Finding{
			Severity:    "info",
			Type:        "subdomain_count",
			Description: fmt.Sprintf("Discovered %d subdomains", len(discoveredSubdomains)),
			Details:     fmt.Sprintf("Found %d interesting subdomains out of %d total", len(interesting), len(discoveredSubdomains)),
		})
	}

	// Check for potential subdomain takeovers
	s.checkSubdomainTakeovers(discoveredSubdomains, result)

	return result
}

// isInterestingSubdomain checks if a subdomain is potentially interesting
func (s *Scanner) isInterestingSubdomain(subdomain string) bool {
	interestingPatterns := []string{
		"admin", "administrator", "api", "app", "auth", "backup", "blog", 
		"cdn", "cms", "cpanel", "dashboard", "db", "demo", "dev", "docs", 
		"ftp", "git", "internal", "jenkins", "jira", "mail", "manage", 
		"old", "panel", "phpmyadmin", "portal", "private", "prometheus", 
		"qa", "redis", "s3", "staging", "stats", "support", "test", 
		"vpn", "wiki", "grafana", "kibana", "elastic", "consul", 
		"vault", "gitlab", "github", "bitbucket", "confluence",
	}

	for _, pattern := range interestingPatterns {
		if contains(subdomain, pattern) {
			return true
		}
	}
	return false
}

// getSubdomainContext provides context about why a subdomain is interesting
func (s *Scanner) getSubdomainContext(subdomain string) string {
	contexts := map[string]string{
		"admin":        "Administrative interface",
		"api":          "API endpoint",
		"auth":         "Authentication service",
		"backup":       "Backup service",
		"cpanel":       "Control panel",
		"db":           "Database service",
		"dev":          "Development environment",
		"ftp":          "File transfer service",
		"git":          "Source control",
		"jenkins":      "CI/CD service",
		"mail":         "Email service",
		"phpmyadmin":   "Database administration",
		"staging":      "Staging environment",
		"test":         "Testing environment",
		"vpn":          "VPN service",
		"prometheus":   "Monitoring service",
		"grafana":      "Metrics dashboard",
		"kibana":       "Log analysis",
		"elastic":      "Search service",
		"consul":       "Service discovery",
		"vault":        "Secrets management",
	}

	for pattern, context := range contexts {
		if contains(subdomain, pattern) {
			return context
		}
	}
	return "Potentially sensitive service"
}

// checkSubdomainTakeovers checks for potential subdomain takeover vulnerabilities
func (s *Scanner) checkSubdomainTakeovers(subdomains []string, result *types.CheckResult) {
	// Limit the number of subdomains to check to avoid excessive scanning
	checkLimit := 20
	if len(subdomains) < checkLimit {
		checkLimit = len(subdomains)
	}

	for i := 0; i < checkLimit; i++ {
		subdomain := subdomains[i]
		
		// Query CNAME for this subdomain
		if cname, err := net.LookupCNAME(subdomain); err == nil && cname != subdomain+"." {
			cnameClean := strings.TrimSuffix(cname, ".")
			if s.isVulnerableService(cnameClean) {
				// Try to resolve the CNAME target
				if _, err := net.LookupHost(cnameClean); err != nil {
					result.Findings = append(result.Findings, types.Finding{
						Severity:    "high",
						Type:        "subdomain_takeover",
						Description: fmt.Sprintf("Potential subdomain takeover: %s", subdomain),
						Details:     fmt.Sprintf("CNAME points to %s which appears to be unclaimed", cnameClean),
					})
					result.Status = "fail"
				}
			}
		}
	}
}

// Helper function to check if a string contains a pattern (case-insensitive)
func contains(s, pattern string) bool {
	return len(s) >= len(pattern) && 
		   (s[:len(pattern)] == pattern || 
			s[len(s)-len(pattern):] == pattern ||
			findInString(s, pattern))
}

func findInString(s, pattern string) bool {
	for i := 0; i <= len(s)-len(pattern); i++ {
		if s[i:i+len(pattern)] == pattern {
			return true
		}
	}
	return false
}