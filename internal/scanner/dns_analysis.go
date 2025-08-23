package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"

	miekgdns "github.com/miekg/dns"
	"github.com/projectdiscovery/dnsx/libs/dnsx"

	"github.com/theopenlane/sleuth/internal/types"
)

// performDNSAnalysis performs comprehensive DNS analysis using dnsx library
func (s *Scanner) performDNSAnalysis(ctx context.Context, domain string) *types.CheckResult {
	result := &types.CheckResult{
		CheckName: "dns_analysis",
		Status:    "pass",
		Findings:  []types.Finding{},
		Metadata:  make(map[string]interface{}),
	}

	dnsResolvers := make([]string, len(s.options.DNSResolvers))
	for i, r := range s.options.DNSResolvers {
		dnsResolvers[i] = fmt.Sprintf("udp:%s:53", r)
	}

	client, err := dnsx.New(dnsx.Options{
		BaseResolvers: dnsResolvers,
		MaxRetries:    s.options.DNSRetries,
		QuestionTypes: []uint16{
			miekgdns.TypeA,
			miekgdns.TypeAAAA,
			miekgdns.TypeCNAME,
			miekgdns.TypeMX,
			miekgdns.TypeTXT,
			miekgdns.TypeNS,
		},
	})
	if err != nil {
		result.Status = "error"
		result.Error = fmt.Sprintf("dnsx init failed: %v", err)
		return result
	}

	data, err := client.QueryMultiple(domain)
	if err != nil {
		return s.performDNSAnalysisNet(ctx, domain)
	}

	records := make(map[string]interface{})

	if len(data.A) > 0 {
		records["A"] = data.A
		result.Metadata["a_records"] = data.A
	}
	if len(data.AAAA) > 0 {
		records["AAAA"] = data.AAAA
		result.Metadata["aaaa_records"] = data.AAAA
	}

	if len(data.CNAME) > 0 {
		cnameClean := strings.TrimSuffix(data.CNAME[0], ".")
		records["CNAME"] = cnameClean
		result.Metadata["cname_records"] = []string{cnameClean}

		if s.isVulnerableService(cnameClean) {
			if ips, err := client.Lookup(cnameClean); err != nil || len(ips) == 0 {
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

	if len(data.MX) > 0 {
		var mxHosts []string
		records["MX"] = data.MX
		result.Metadata["mx_records"] = data.MX
		for _, mx := range data.MX {
			parts := strings.Fields(mx)
			if len(parts) > 0 {
				mxHosts = append(mxHosts, strings.TrimSuffix(parts[len(parts)-1], "."))
			}
		}
		s.analyzeEmailProvider(mxHosts, result)
	}

	if len(data.TXT) > 0 {
		records["TXT"] = data.TXT
		result.Metadata["txt_records"] = data.TXT
		s.analyzeTXTRecords(data.TXT, result)
	}

	if len(data.NS) > 0 {
		nsClean := make([]string, len(data.NS))
		for i, ns := range data.NS {
			nsClean[i] = strings.TrimSuffix(ns, ".")
		}
		records["NS"] = nsClean
		result.Metadata["ns_records"] = nsClean
	}

	result.Metadata["dns_records"] = records
	return result
}

// performDNSAnalysisNet performs DNS analysis using net package as fallback
func (s *Scanner) performDNSAnalysisNet(ctx context.Context, domain string) *types.CheckResult {
	result := &types.CheckResult{
		CheckName: "dns_analysis",
		Status:    "pass",
		Findings:  []types.Finding{},
		Metadata:  make(map[string]interface{}),
	}

	records := make(map[string]interface{})

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

	if cname, err := net.LookupCNAME(domain); err == nil && cname != domain+"." {
		cnameClean := strings.TrimSuffix(cname, ".")
		records["CNAME"] = cnameClean
		result.Metadata["cname_records"] = []string{cnameClean}

		if s.isVulnerableService(cnameClean) {
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
		s.analyzeEmailProvider(mxHosts, result)
	}

	if txtRecords, err := net.LookupTXT(domain); err == nil && len(txtRecords) > 0 {
		records["TXT"] = txtRecords
		result.Metadata["txt_records"] = txtRecords
		s.analyzeTXTRecords(txtRecords, result)
	}

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
		"google.com":             "Google Workspace",
		"googlemail.com":         "Google Workspace",
		"outlook.com":            "Microsoft 365",
		"protection.outlook.com": "Microsoft 365",
		"pphosted.com":           "Proofpoint",
		"mimecast.com":           "Mimecast",
		"messagelabs.com":        "Symantec MessageLabs",
		"barracuda.com":          "Barracuda",
		"mailgun.org":            "Mailgun",
		"sendgrid.net":           "SendGrid",
		"amazonses.com":          "Amazon SES",
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
