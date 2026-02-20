package compliance

import "regexp"

const (
	// PageTypePrivacyPolicy identifies privacy policy pages
	PageTypePrivacyPolicy = "privacy_policy"
	// PageTypeTermsOfService identifies terms of service pages
	PageTypeTermsOfService = "terms_of_service"
	// PageTypeTrustCenter identifies trust center pages
	PageTypeTrustCenter = "trust_center"
	// PageTypeDPA identifies data processing agreement pages
	PageTypeDPA = "dpa"
	// PageTypeSOC2Report identifies SOC 2 report pages
	PageTypeSOC2Report = "soc2_report"
	// PageTypeSecurity identifies security policy pages
	PageTypeSecurity = "security"
	// PageTypeSubprocessors identifies subprocessor list pages
	PageTypeSubprocessors = "subprocessors"
	// PageTypeCookiePolicy identifies cookie policy pages
	PageTypeCookiePolicy = "cookie_policy"
	// PageTypeGDPR identifies GDPR-specific pages
	PageTypeGDPR = "gdpr"
)

// ClassifiedPage holds a probed URL and its regex-based classification
type ClassifiedPage struct {
	// URL is the final resolved URL after redirects
	URL string
	// Title is the page title extracted from HTML
	Title string
	// PageType is the regex-determined classification
	PageType string
	// StatusCode is the HTTP status code
	StatusCode int
	// Frameworks lists compliance frameworks detected in page content
	Frameworks []string
}

// classificationRule defines regex patterns for a single page type
type classificationRule struct {
	pageType      string
	urlPatterns   []*regexp.Regexp
	titlePatterns []*regexp.Regexp
	bodyPatterns  []*regexp.Regexp
}

// classificationRules is the ordered list of classification rules; first match wins
var classificationRules []classificationRule

func init() {
	classificationRules = []classificationRule{
		{
			pageType: PageTypePrivacyPolicy,
			urlPatterns: compileAll(
				`(?i)/privac(y|y-policy|y-notice)`,
				`(?i)/legal/privac`,
				`(?i)/data-protection`,
			),
			titlePatterns: compileAll(
				`(?i)privacy\s+(policy|notice|statement)`,
				`(?i)data\s+protection\s+(policy|notice)`,
			),
			bodyPatterns: compileAll(
				`(?i)personal\s+(data|information).{0,80}collect`,
				`(?i)we\s+collect\s+.{0,40}(personal|information)`,
				`(?i)this\s+privacy\s+(policy|notice)`,
			),
		},
		{
			pageType: PageTypeTermsOfService,
			urlPatterns: compileAll(
				`(?i)/(terms|tos)(/|$)`,
				`(?i)/terms-of-(service|use)`,
				`(?i)/legal/terms`,
			),
			titlePatterns: compileAll(
				`(?i)terms\s+(of\s+service|of\s+use|&\s+conditions|and\s+conditions)`,
			),
			bodyPatterns: compileAll(
				`(?i)(binding\s+agreement|user\s+agreement|these\s+terms\s+govern)`,
				`(?i)by\s+(using|accessing).{0,40}you\s+agree`,
			),
		},
		{
			pageType: PageTypeTrustCenter,
			urlPatterns: compileAll(
				`(?i)^https?://trust\.`,
				`(?i)/trust(-center|center)?(/|$)`,
			),
			titlePatterns: compileAll(
				`(?i)trust\s*(center|portal|hub|page)`,
			),
			bodyPatterns: compileAll(
				`(?i)security\s+certifications?`,
				`(?i)compliance\s+program`,
				`(?i)trust\s+and\s+security`,
			),
		},
		{
			pageType: PageTypeDPA,
			urlPatterns: compileAll(
				`(?i)/(dpa|data-processing)`,
				`(?i)/legal/dpa`,
			),
			titlePatterns: compileAll(
				`(?i)data\s+processing\s+(agreement|addendum)`,
			),
			bodyPatterns: compileAll(
				`(?i)data\s+processor\b`,
				`(?i)standard\s+contractual\s+clauses`,
			),
		},
		{
			pageType: PageTypeSOC2Report,
			urlPatterns: compileAll(
				`(?i)/soc-?2`,
			),
			titlePatterns: compileAll(
				`(?i)soc\s*2`,
			),
			bodyPatterns: compileAll(
				`(?i)soc\s*2\s*type\s*(ii|i|1|2)`,
				`(?i)service\s+organization\s+control`,
			),
		},
		{
			pageType: PageTypeSecurity,
			urlPatterns: compileAll(
				`(?i)^https?://security\.`,
				`(?i)/security(/|$)`,
				`(?i)/security\.txt$`,
				`(?i)/\.well-known/security\.txt$`,
			),
			titlePatterns: compileAll(
				`(?i)^security(\s+policy)?$`,
				`(?i)security\s+(overview|practices|program)`,
			),
			bodyPatterns: compileAll(
				`(?i)vulnerability\s+disclosure`,
				`(?i)responsible\s+disclosure`,
				`(?i)bug\s+bounty`,
				`(?i)security\s+practices`,
			),
		},
		{
			pageType: PageTypeSubprocessors,
			urlPatterns: compileAll(
				`(?i)/sub-?processors`,
			),
			titlePatterns: compileAll(
				`(?i)sub-?processors`,
			),
			bodyPatterns: compileAll(
				`(?i)sub-?processor\s+list`,
				`(?i)third.party\s+sub-?processors`,
			),
		},
		{
			pageType: PageTypeCookiePolicy,
			urlPatterns: compileAll(
				`(?i)/(cookie-?policy|cookies)(/|$)`,
			),
			titlePatterns: compileAll(
				`(?i)cookie\s+(policy|notice|statement)`,
			),
			bodyPatterns: compileAll(
				`(?i)we\s+use\s+cookies`,
				`(?i)cookie\s+categories`,
				`(?i)strictly\s+necessary\s+cookies`,
			),
		},
		{
			pageType: PageTypeGDPR,
			urlPatterns: compileAll(
				`(?i)/gdpr`,
			),
			titlePatterns: compileAll(
				`(?i)gdpr\s+(compliance|notice|rights|statement)`,
			),
			bodyPatterns: compileAll(
				`(?i)general\s+data\s+protection\s+regulation`,
				`(?i)data\s+subject\s+rights`,
				`(?i)right\s+to\s+erasure`,
			),
		},
	}
}

// ClassifyPage determines the page type from URL, title, and body content.
// URL patterns are checked first across all rules, then title patterns,
// then body patterns. This ensures a URL match always beats a body match
// from a higher-priority rule. Returns the matching page type constant
// or empty string if no match.
func ClassifyPage(pageURL, title, body string) string {
	// Pass 1: check URL patterns (highest confidence)
	for _, rule := range classificationRules {
		if matchesAny(rule.urlPatterns, pageURL) {
			return rule.pageType
		}
	}

	// Pass 2: check title patterns
	for _, rule := range classificationRules {
		if matchesAny(rule.titlePatterns, title) {
			return rule.pageType
		}
	}

	// Pass 3: check body patterns (lowest confidence)
	for _, rule := range classificationRules {
		if matchesAny(rule.bodyPatterns, body) {
			return rule.pageType
		}
	}

	return ""
}

// compileAll compiles multiple regex patterns, panicking on invalid patterns
func compileAll(patterns ...string) []*regexp.Regexp {
	compiled := make([]*regexp.Regexp, 0, len(patterns))

	for _, p := range patterns {
		compiled = append(compiled, regexp.MustCompile(p))
	}

	return compiled
}

// matchesAny returns true if the input matches any of the compiled patterns
func matchesAny(patterns []*regexp.Regexp, input string) bool {
	for _, p := range patterns {
		if p.MatchString(input) {
			return true
		}
	}

	return false
}
