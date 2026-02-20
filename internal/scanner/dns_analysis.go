package scanner

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"

	miekgdns "github.com/miekg/dns"
	"github.com/projectdiscovery/dnsx/libs/dnsx"

	"github.com/theopenlane/sleuth/internal/types"
)

// verificationServiceMap maps TXT record key prefixes to the service they confirm usage of
var verificationServiceMap = map[string]string{
	"google-site-verification":       "Google Workspace",
	"facebook-domain-verification":   "Facebook / Meta",
	"apple-domain-verification":      "Apple",
	"slack-domain-verification":      "Slack",
	"hubspot-domain-verification":    "HubSpot",
	"atlassian-domain-verification":  "Atlassian",
	"docusign":                       "DocuSign",
	"stripe-verification":            "Stripe",
	"zoom-domain-verification":       "Zoom",
	"miro-verification":              "Miro",
	"ms":                             "Microsoft 365",
	"webexdomainverification":        "Cisco Webex",
	"have-i-been-pwned-verification": "Have I Been Pwned",
	"adobe-idp-site-verification":    "Adobe",
	"cloudflare-domain-verification": "Cloudflare",
	"brevo-code":                     "Brevo",
	"intercom-verification":          "Intercom",
	"pinterest-site-verification":    "Pinterest",
	"duo_sso_verification":           "Duo Security",
	"1password-site-verification":    "1Password",
	"knowbe4-site-verification":      "KnowBe4",
	"calendly-site-verification":     "Calendly",
	"postman-domain-verification":    "Postman",
	"logmein-verification-code":      "LogMeIn",
	"onetrust-domain-verification":   "OneTrust",
	"sophos-domain-verification":     "Sophos",
	"drift-domain-verification":      "Drift",
	"yandex-verification":            "Yandex",
}

// performDNSAnalysis performs comprehensive DNS analysis using dnsx library.
func (s *Scanner) performDNSAnalysis(ctx context.Context, domain string) *types.CheckResult {
	result := newCheckResult("dns_analysis")

	dnsResolvers := make([]string, len(s.options.DNSResolvers))
	for i, resolver := range s.options.DNSResolvers {
		dnsResolvers[i] = fmt.Sprintf("udp:%s:53", resolver)
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
		markCheckError(result, "dnsx init failed: %v", err)
		return result
	}

	data, err := client.QueryMultiple(domain)
	if err != nil {
		return s.performDNSAnalysisNet(ctx, domain)
	}

	records := make(map[string]any)

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

		if fingerprint, ok := s.takeoverFingerprintForCNAME(cnameClean); ok {
			if confirmed, evidence := s.confirmSubdomainTakeover(ctx, domain, cnameClean, fingerprint); confirmed {
				result.Findings = append(result.Findings, types.Finding{
					Severity:    "high",
					Type:        "cname_takeover",
					Description: fmt.Sprintf("Confirmed CNAME takeover risk for %s", domain),
					Details:     evidence,
				})
				markCheckFailed(result)
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

// performDNSAnalysisNet performs DNS analysis using the standard net package as fallback.
func (s *Scanner) performDNSAnalysisNet(ctx context.Context, domain string) *types.CheckResult {
	result := newCheckResult("dns_analysis")
	resolver := net.DefaultResolver
	records := make(map[string]any)

	dnsCtx, cancel := s.withDNSTimeout(ctx)
	defer cancel()

	if addrs, err := resolver.LookupIPAddr(dnsCtx, domain); err == nil && len(addrs) > 0 {
		var ipv4s, ipv6s []string
		for _, addr := range addrs {
			if addr.IP.To4() != nil {
				ipv4s = append(ipv4s, addr.IP.String())
			} else {
				ipv6s = append(ipv6s, addr.IP.String())
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

	if cname, err := resolver.LookupCNAME(dnsCtx, domain); err == nil && cname != domain+"." {
		cnameClean := strings.TrimSuffix(cname, ".")
		records["CNAME"] = cnameClean
		result.Metadata["cname_records"] = []string{cnameClean}

		if fingerprint, ok := s.takeoverFingerprintForCNAME(cnameClean); ok {
			if confirmed, evidence := s.confirmSubdomainTakeover(ctx, domain, cnameClean, fingerprint); confirmed {
				result.Findings = append(result.Findings, types.Finding{
					Severity:    "high",
					Type:        "cname_takeover",
					Description: fmt.Sprintf("Confirmed CNAME takeover risk for %s", domain),
					Details:     evidence,
				})
				markCheckFailed(result)
			}
		}
	}

	if mxRecords, err := resolver.LookupMX(dnsCtx, domain); err == nil && len(mxRecords) > 0 {
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

	if txtRecords, err := resolver.LookupTXT(dnsCtx, domain); err == nil && len(txtRecords) > 0 {
		records["TXT"] = txtRecords
		result.Metadata["txt_records"] = txtRecords
		s.analyzeTXTRecords(txtRecords, result)
	}

	if nsRecords, err := resolver.LookupNS(dnsCtx, domain); err == nil && len(nsRecords) > 0 {
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

// analyzeEmailProvider identifies email service providers from MX records.
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
		for providerDomain, provider := range providers {
			if strings.Contains(host, providerDomain) {
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

// analyzeTXTRecords analyzes TXT records for security configurations.
func (s *Scanner) analyzeTXTRecords(txtRecords []string, result *types.CheckResult) {
	var (
		hasSPF    bool
		spfRecord string
	)

	for _, txt := range txtRecords {
		lower := strings.ToLower(txt)

		if strings.HasPrefix(lower, "v=spf1") {
			hasSPF = true
			spfRecord = txt
			result.Metadata["spf"] = spfRecord

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

		if strings.HasPrefix(lower, "v=dmarc1") {
			result.Metadata["dmarc"] = txt
		}

		s.detectVerificationServices(lower, txt, result)
	}

	s.finalizeDetectedServices(result)

	if !hasSPF {
		result.Findings = append(result.Findings, types.Finding{
			Severity:    "medium",
			Type:        "missing_spf",
			Description: "No SPF record found",
			Details:     "SPF helps prevent email spoofing",
		})
	}
}

// detectVerificationServices checks a TXT record against known domain verification prefixes
// and emits both a domain_verification finding and a service_detection finding when matched.
func (s *Scanner) detectVerificationServices(lower, original string, result *types.CheckResult) {
	for prefix, service := range verificationServiceMap {
		if !strings.HasPrefix(lower, prefix+"=") && !strings.HasPrefix(lower, prefix+":") {
			continue
		}

		result.Findings = append(result.Findings, types.Finding{
			Severity:    "info",
			Type:        "domain_verification",
			Description: "Domain verification record found",
			Details:     original,
		})

		// Track detected services for dedup and metadata aggregation
		serviceSet, _ := result.Metadata["_service_set"].(map[string]struct{})
		if serviceSet == nil {
			serviceSet = make(map[string]struct{})
		}

		if _, exists := serviceSet[service]; !exists {
			serviceSet[service] = struct{}{}
			result.Metadata["_service_set"] = serviceSet

			result.Findings = append(result.Findings, types.Finding{
				Severity:    "info",
				Type:        "service_detection",
				Description: fmt.Sprintf("Service: %s", service),
				Details:     fmt.Sprintf("Domain verification TXT record confirms usage of %s", service),
			})
		}

		return
	}

	// Generic verification record that didn't match a known service
	if strings.Contains(lower, "verification=") || strings.Contains(lower, "verify=") {
		result.Findings = append(result.Findings, types.Finding{
			Severity:    "info",
			Type:        "domain_verification",
			Description: "Domain verification record found",
			Details:     original,
		})
	}
}

// finalizeDetectedServices converts the internal service set to a sorted metadata list
// and removes the temporary working set.
func (s *Scanner) finalizeDetectedServices(result *types.CheckResult) {
	serviceSet, _ := result.Metadata["_service_set"].(map[string]struct{})
	delete(result.Metadata, "_service_set")

	if len(serviceSet) == 0 {
		return
	}

	services := make([]string, 0, len(serviceSet))
	for svc := range serviceSet {
		services = append(services, svc)
	}

	sort.Strings(services)
	result.Metadata["detected_services"] = services
}
