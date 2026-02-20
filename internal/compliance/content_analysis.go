package compliance

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

const (
	// negationWindowBefore is the number of characters before a match to check
	// for aspirational/planning context that would negate the detection.
	negationWindowBefore = 80
	// negationWindowAfter is the number of characters after a match to check
	// for aspirational/planning context that would negate the detection.
	negationWindowAfter = 50
)

// metaTagPattern matches HTML meta tags to strip them before content analysis.
// This prevents false positives from platform boilerplate (e.g., Drata trust
// center templates that embed "SOC 2, ISO 27001" in meta keywords regardless
// of the customer's actual certifications).
var metaTagPattern = regexp.MustCompile(`(?i)<meta\s[^>]*>`)

// negativeContextPattern matches phrases that indicate aspirational or planned
// compliance status rather than achieved certification. Used to prevent false
// positives from statements like "preparing to get our SOC 2".
var negativeContextPattern = regexp.MustCompile(`(?i)\b(preparing|pursuing|working\s+toward|planned|planning|roadmap|in\s+progress|upcoming|aspiring|intending|evaluating|considering|exploring|investigating|future|goal|target|aiming|expect\s+to|plan\s+to|hope\s+to|looking\s+into)\b`)

// stripMetaTags removes all <meta> tags from HTML to isolate visible page content.
func stripMetaTags(html string) string {
	return metaTagPattern.ReplaceAllString(html, "")
}

// complianceBodyIndicators maps page types to patterns that indicate compliance
// coverage when found in trust center or security page body content.
var complianceBodyIndicators = []struct {
	pageType string
	patterns []*regexp.Regexp
}{
	{
		pageType: PageTypeSOC2Report,
		patterns: compileAll(
			`(?i)\bsoc\s*2\b`,
			`(?i)service\s+organization\s+control`,
			`(?i)\bsoc\s+2\s+type\s*(ii|i|1|2)\b`,
			`(?i)\bssae\s*(16|18)\b`,
		),
	},
	{
		pageType: PageTypeSubprocessors,
		patterns: compileAll(
			`(?i)\bsub-?processors?\b`,
			`(?i)third.party\s+(vendors?|sub-?processors?)`,
			`(?i)\bvendor\s+list\b`,
		),
	},
	{
		pageType: PageTypeDPA,
		patterns: compileAll(
			`(?i)\bdata\s+processing\s+(agreement|addendum)\b`,
			`(?i)\bdpa\b.*\b(download|request|sign)\b`,
		),
	},
	{
		pageType: PageTypePrivacyPolicy,
		patterns: compileAll(
			`(?i)\bprivacy\s+policy\b`,
			`(?i)\bdata\s+protection\s+policy\b`,
		),
	},
	{
		pageType: PageTypeTermsOfService,
		patterns: compileAll(
			`(?i)\bterms\s+(of\s+service|of\s+use|&\s+conditions|and\s+conditions)\b`,
		),
	},
}

// frameworkIndicators maps framework names to body patterns that confirm their
// presence on trust center or security pages.
var frameworkIndicators = []struct {
	framework string
	patterns  []*regexp.Regexp
}{
	{framework: "SOC 2", patterns: compileAll(`(?i)\bsoc\s*2\b`)},
	{framework: "ISO 27001", patterns: compileAll(`(?i)\biso\s*27001\b`)},
	{framework: "HIPAA", patterns: compileAll(`(?i)\bhipaa\b`)},
	{framework: "PCI DSS", patterns: compileAll(`(?i)\bpci[\s-]*dss\b`)},
	{framework: "GDPR", patterns: compileAll(`(?i)\bgdpr\b`)},
	{framework: "CCPA", patterns: compileAll(`(?i)\bccpa\b`)},
	{framework: "FedRAMP", patterns: compileAll(`(?i)\bfedramp\b`)},
	{framework: "SOC 1", patterns: compileAll(`(?i)\bsoc\s*1\b`)},
	{framework: "SOC 3", patterns: compileAll(`(?i)\bsoc\s*3\b`)},
	{framework: "CSA STAR", patterns: compileAll(`(?i)\bcsa\s+star\b`)},
	{framework: "NIST", patterns: compileAll(`(?i)\bnist\b`)},
}

// TrustCenterAnalysis holds results from scanning trust center page content.
type TrustCenterAnalysis struct {
	// InferredPages are compliance pages inferred from body content mentions.
	InferredPages []ClassifiedPage
	// ExternalLinks are compliance-related links found pointing to external domains.
	ExternalLinks []string
	// Frameworks are compliance framework names detected in the body text.
	Frameworks []string
}

// AnalyzeTrustCenterContent scans an HTML body (from a trust center or security
// page) for compliance indicators, framework mentions, and external compliance links.
// The parentPageURL is used to resolve relative hrefs and to set as the URL for
// inferred pages that are discovered from body content rather than dedicated pages.
func AnalyzeTrustCenterContent(body, parentPageURL, baseDomain string) TrustCenterAnalysis {
	var analysis TrustCenterAnalysis

	// Strip meta tags to avoid matching platform boilerplate (e.g., Drata
	// templates embed "SOC 2, ISO 27001" in meta keywords for all customers)
	cleanBody := stripMetaTags(body)

	// Scan body for compliance indicators to create inferred pages.
	// Uses affirmative matching to avoid false positives from aspirational
	// statements like "preparing to get our SOC 2".
	seen := make(map[string]struct{})

	for _, indicator := range complianceBodyIndicators {
		if _, already := seen[indicator.pageType]; already {
			continue
		}

		if matchesAffirmatively(indicator.patterns, cleanBody) {
			seen[indicator.pageType] = struct{}{}
			analysis.InferredPages = append(analysis.InferredPages, ClassifiedPage{
				URL:        parentPageURL,
				Title:      fmt.Sprintf("%s (from trust center)", pageTypeLabel(indicator.pageType)),
				PageType:   indicator.pageType,
				StatusCode: httpSuccessStatus,
			})
		}
	}

	// Scan for framework mentions using affirmative matching
	frameworkSeen := make(map[string]struct{})

	for _, fi := range frameworkIndicators {
		if _, already := frameworkSeen[fi.framework]; already {
			continue
		}

		if matchesAffirmatively(fi.patterns, cleanBody) {
			frameworkSeen[fi.framework] = struct{}{}
			analysis.Frameworks = append(analysis.Frameworks, fi.framework)
		}
	}

	// Extract external compliance links
	analysis.ExternalLinks = extractExternalComplianceLinks(body, baseDomain)

	return analysis
}

// pageTypeLabel returns a human-readable label for a page type constant.
func pageTypeLabel(pageType string) string {
	labels := map[string]string{
		PageTypePrivacyPolicy:  "Privacy Policy",
		PageTypeTermsOfService: "Terms of Service",
		PageTypeTrustCenter:    "Trust Center",
		PageTypeDPA:            "Data Processing Agreement",
		PageTypeSOC2Report:     "SOC 2",
		PageTypeSecurity:       "Security",
		PageTypeSubprocessors:  "Subprocessors",
		PageTypeCookiePolicy:   "Cookie Policy",
		PageTypeGDPR:           "GDPR",
	}

	if label, ok := labels[pageType]; ok {
		return label
	}

	return pageType
}

// matchesAffirmatively returns true if any pattern matches the text AND the
// match is not negated by nearby aspirational/planning context words. This
// prevents false positives from statements like "preparing to get our SOC 2"
// or "pursuing ISO 27001 certification".
func matchesAffirmatively(patterns []*regexp.Regexp, text string) bool {
	for _, p := range patterns {
		locs := p.FindAllStringIndex(text, -1)
		for _, loc := range locs {
			if !isNegatedByContext(text, loc[0], loc[1]) {
				return true
			}
		}
	}

	return false
}

// isNegatedByContext checks whether a regex match at a given position in the
// text is surrounded by words indicating aspirational rather than achieved status.
func isNegatedByContext(text string, matchStart, matchEnd int) bool {
	windowStart := max(matchStart-negationWindowBefore, 0)
	windowEnd := min(matchEnd+negationWindowAfter, len(text))
	window := text[windowStart:windowEnd]

	return negativeContextPattern.MatchString(window)
}

// extractExternalComplianceLinks finds compliance-related links that point to
// external domains (not the base domain or its subdomains).
func extractExternalComplianceLinks(body, baseDomain string) []string {
	matches := linkPattern.FindAllStringSubmatch(body, -1)

	seen := make(map[string]struct{})
	var links []string

	for _, match := range matches {
		if len(match) < minRegexMatchGroups {
			continue
		}

		href := strings.TrimSpace(match[1])
		if href == "" || strings.HasPrefix(href, "#") || strings.HasPrefix(href, "javascript:") {
			continue
		}

		// Only interested in absolute URLs to external domains
		parsed, err := url.Parse(href)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			continue
		}

		host := parsed.Hostname()

		// Skip same-domain links (already handled by deep crawl)
		if host == baseDomain || strings.HasSuffix(host, "."+baseDomain) {
			continue
		}

		// Must be compliance-related
		if !complianceLinkFilter.MatchString(href) {
			continue
		}

		normalized := parsed.String()
		if _, ok := seen[normalized]; ok {
			continue
		}

		seen[normalized] = struct{}{}
		links = append(links, normalized)
	}

	return links
}
