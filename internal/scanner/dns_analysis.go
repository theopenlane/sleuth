package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/theopenlane/sleuth/internal/types"
)

// performDNSAnalysis performs comprehensive DNS analysis using Go's net package
func (s *Scanner) performDNSAnalysis(ctx context.Context, domain string) *types.CheckResult {
	result := &types.CheckResult{
		CheckName: "dns_analysis",
		Status:    "pass",
		Findings:  []types.Finding{},
		Metadata:  make(map[string]interface{}),
	}

	records := make(map[string]interface{})

	// Query A records
	if ips, err := net.LookupIP(domain); err == nil && len(ips) > 0 {
		var ipv4s, ipv6s []string
		for _, ip := range ips {
			if ip.To4() != nil {
				ipv4s = append(ipv4s, ip.String())
			} else {
				ipv6s = append(ipv6s, ip.String())
			}
		}
		if len(ipv4s) > 0 {
			records["A"] = ipv4s
			result.Metadata["a_records"] = ipv4s
		}
		if len(ipv6s) > 0 {
			records["AAAA"] = ipv6s
			result.Metadata["aaaa_records"] = ipv6s
		}
	}

	// Query CNAME records
	if cname, err := net.LookupCNAME(domain); err == nil && cname != domain+"." {
		cnameClean := strings.TrimSuffix(cname, ".")
		records["CNAME"] = cnameClean
		result.Metadata["cname_records"] = []string{cnameClean}
		
		// Check for potential CNAME takeover
		if s.isVulnerableService(cnameClean) {
			// Try to resolve the CNAME target
			if _, err := net.LookupHost(cnameClean); err != nil {
				result.Findings = append(result.Findings, types.Finding{
					Severity:    "high",
					Type:        "cname_takeover",
					Description: fmt.Sprintf("Potential CNAME takeover vulnerability for %s", domain),
					Details:     fmt.Sprintf("CNAME points to %s which appears to be unclaimed", cnameClean),
				})
				result.Status = "fail"
			}
		}
	}

	// Query MX records
	if mxRecords, err := net.LookupMX(domain); err == nil && len(mxRecords) > 0 {
		var mxs []string
		var mxHosts []string
		for _, mx := range mxRecords {
			mxStr := fmt.Sprintf("%d %s", mx.Pref, strings.TrimSuffix(mx.Host, "."))
			mxs = append(mxs, mxStr)
			mxHosts = append(mxHosts, strings.TrimSuffix(mx.Host, "."))
		}
		records["MX"] = mxs
		result.Metadata["mx_records"] = mxs
		
		// Analyze email providers
		s.analyzeEmailProvider(mxHosts, result)
	}

	// Query TXT records
	if txtRecords, err := net.LookupTXT(domain); err == nil && len(txtRecords) > 0 {
		records["TXT"] = txtRecords
		result.Metadata["txt_records"] = txtRecords
		
		// Analyze TXT records for security configurations
		s.analyzeTXTRecords(txtRecords, result)
	}

	// Query NS records
	if nsRecords, err := net.LookupNS(domain); err == nil && len(nsRecords) > 0 {
		var nss []string
		for _, ns := range nsRecords {
			nss = append(nss, strings.TrimSuffix(ns.Host, "."))
		}
		records["NS"] = nss
		result.Metadata["ns_records"] = nss
	}

	result.Metadata["dns_records"] = records
	return result
}

// isVulnerableService checks if a CNAME target is potentially vulnerable
func (s *Scanner) isVulnerableService(cname string) bool {
	vulnerablePatterns := []string{
		".herokuapp.com",
		".azurewebsites.net",
		".cloudapp.net",
		".cloudapp.azure.com",
		".s3.amazonaws.com",
		".s3-website",
		".github.io",
		".gitlab.io",
		".surge.sh",
		".bitbucket.io",
		".ghost.io",
		".zendesk.com",
		".desk.com",
		".fastly.net",
		".feedpress.me",
		".shopify.com",
		".statuspage.io",
		".uservoice.com",
		".wpengine.com",
		".pantheonsite.io",
		".teamwork.com",
		".helpjuice.com",
		".helpscoutdocs.com",
		".cargo.site",
		".cargocollective.com",
		".redirect.pizza",
	}

	cname = strings.ToLower(strings.TrimSuffix(cname, "."))
	for _, pattern := range vulnerablePatterns {
		if strings.HasSuffix(cname, pattern) {
			return true
		}
	}
	return false
}

// analyzeEmailProvider identifies email service providers from MX records
func (s *Scanner) analyzeEmailProvider(mxHosts []string, result *types.CheckResult) {
	providers := map[string]string{
		"google.com":               "Google Workspace",
		"googlemail.com":           "Google Workspace",
		"outlook.com":              "Microsoft 365",
		"protection.outlook.com":   "Microsoft 365",
		"pphosted.com":             "Proofpoint",
		"mimecast.com":             "Mimecast",
		"messagelabs.com":          "Symantec MessageLabs",
		"barracuda.com":            "Barracuda",
		"mailgun.org":              "Mailgun",
		"sendgrid.net":             "SendGrid",
		"amazonses.com":            "Amazon SES",
	}

	for _, mx := range mxHosts {
		host := strings.ToLower(mx)
		for domain, provider := range providers {
			if strings.Contains(host, domain) {
				result.Findings = append(result.Findings, types.Finding{
					Severity:    "info",
					Type:        "email_provider",
					Description: fmt.Sprintf("Email hosted by %s", provider),
					Details:     fmt.Sprintf("MX record: %s", mx),
				})
				return
			}
		}
	}
}

// analyzeTXTRecords analyzes TXT records for security configurations
func (s *Scanner) analyzeTXTRecords(txtRecords []string, result *types.CheckResult) {
	var hasSPF bool
	var spfRecord string

	for _, txt := range txtRecords {
		lower := strings.ToLower(txt)
		
		// SPF record analysis
		if strings.HasPrefix(lower, "v=spf1") {
			hasSPF = true
			spfRecord = txt
			result.Metadata["spf"] = spfRecord
			
			// Check for weak SPF policies
			if strings.Contains(lower, "+all") {
				result.Findings = append(result.Findings, types.Finding{
					Severity:    "high",
					Type:        "weak_spf",
					Description: "SPF record allows all servers (+all)",
					Details:     txt,
				})
			} else if strings.Contains(lower, "?all") {
				result.Findings = append(result.Findings, types.Finding{
					Severity:    "medium",
					Type:        "weak_spf",
					Description: "SPF record has neutral policy (?all)",
					Details:     txt,
				})
			}
		}
		
		// DMARC record analysis (informational only)
		if strings.HasPrefix(lower, "v=dmarc1") {
			result.Metadata["dmarc"] = txt
		}
		
		// Domain verification records
		if strings.Contains(lower, "verification=") || 
		   strings.Contains(lower, "google-site-verification=") ||
		   strings.Contains(lower, "facebook-domain-verification=") ||
		   strings.Contains(lower, "MS=") ||
		   strings.Contains(lower, "apple-domain-verification=") {
			result.Findings = append(result.Findings, types.Finding{
				Severity:    "info",
				Type:        "domain_verification",
				Description: "Domain verification record found",
				Details:     txt,
			})
		}
	}

	// Report missing SPF
	if !hasSPF {
		result.Findings = append(result.Findings, types.Finding{
			Severity:    "medium",
			Type:        "missing_spf",
			Description: "No SPF record found",
			Details:     "SPF helps prevent email spoofing",
		})
	}
}