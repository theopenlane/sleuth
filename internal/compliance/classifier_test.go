package compliance

import "testing"

func TestClassifyPage_URLMatch(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected string
	}{
		{"privacy policy path", "https://example.com/privacy", PageTypePrivacyPolicy},
		{"privacy policy hyphenated", "https://example.com/privacy-policy", PageTypePrivacyPolicy},
		{"legal privacy", "https://example.com/legal/privacy", PageTypePrivacyPolicy},
		{"terms path", "https://example.com/terms", PageTypeTermsOfService},
		{"tos path", "https://example.com/tos", PageTypeTermsOfService},
		{"terms of service", "https://example.com/terms-of-service", PageTypeTermsOfService},
		{"trust center", "https://example.com/trust-center", PageTypeTrustCenter},
		{"trust path", "https://example.com/trust", PageTypeTrustCenter},
		{"trust subdomain", "https://trust.example.com/", PageTypeTrustCenter},
		{"trust subdomain no trailing slash", "https://trust.example.com", PageTypeTrustCenter},
		{"dpa path", "https://example.com/dpa", PageTypeDPA},
		{"data processing", "https://example.com/data-processing-agreement", PageTypeDPA},
		{"soc2 path", "https://example.com/soc2", PageTypeSOC2Report},
		{"soc-2 path", "https://example.com/soc-2", PageTypeSOC2Report},
		{"security path", "https://example.com/security", PageTypeSecurity},
		{"security.txt", "https://example.com/security.txt", PageTypeSecurity},
		{"well-known security", "https://example.com/.well-known/security.txt", PageTypeSecurity},
		{"security subdomain", "https://security.example.com/", PageTypeSecurity},
		{"subprocessors", "https://example.com/subprocessors", PageTypeSubprocessors},
		{"sub-processors", "https://example.com/sub-processors", PageTypeSubprocessors},
		{"cookie policy", "https://example.com/cookie-policy", PageTypeCookiePolicy},
		{"cookies path", "https://example.com/cookies", PageTypeCookiePolicy},
		{"gdpr path", "https://example.com/gdpr", PageTypeGDPR},
		{"no match", "https://example.com/about", ""},
		{"no match blog", "https://example.com/blog/post-1", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ClassifyPage(tc.url, "", "")
			if result != tc.expected {
				t.Errorf("ClassifyPage(%q, \"\", \"\"): expected %q, got %q", tc.url, tc.expected, result)
			}
		})
	}
}

func TestClassifyPage_TitleMatch(t *testing.T) {
	tests := []struct {
		name     string
		title    string
		expected string
	}{
		{"privacy policy title", "Privacy Policy", PageTypePrivacyPolicy},
		{"privacy notice title", "Privacy Notice - Acme Corp", PageTypePrivacyPolicy},
		{"privacy statement", "Data Protection Policy", PageTypePrivacyPolicy},
		{"terms of service", "Terms of Service", PageTypeTermsOfService},
		{"terms of use", "Terms of Use", PageTypeTermsOfService},
		{"terms and conditions", "Terms & Conditions", PageTypeTermsOfService},
		{"trust center", "Trust Center", PageTypeTrustCenter},
		{"trust portal", "Trust Portal", PageTypeTrustCenter},
		{"dpa title", "Data Processing Agreement", PageTypeDPA},
		{"dpa addendum", "Data Processing Addendum", PageTypeDPA},
		{"soc 2 title", "SOC 2 Report", PageTypeSOC2Report},
		{"security title", "Security", PageTypeSecurity},
		{"security practices", "Security Practices", PageTypeSecurity},
		{"subprocessors title", "Sub-processors", PageTypeSubprocessors},
		{"subprocessors no hyphen", "Subprocessors", PageTypeSubprocessors},
		{"cookie policy title", "Cookie Policy", PageTypeCookiePolicy},
		{"cookie notice", "Cookie Notice", PageTypeCookiePolicy},
		{"gdpr compliance", "GDPR Compliance", PageTypeGDPR},
		{"no match", "About Us", ""},
		{"no match pricing", "Pricing Plans", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ClassifyPage("https://example.com/page", tc.title, "")
			if result != tc.expected {
				t.Errorf("ClassifyPage(_, %q, \"\"): expected %q, got %q", tc.title, tc.expected, result)
			}
		})
	}
}

func TestClassifyPage_BodyMatch(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected string
	}{
		{
			"privacy body",
			"We collect personal data to provide our services.",
			PageTypePrivacyPolicy,
		},
		{
			"privacy notice body",
			"This privacy policy describes how we handle your information.",
			PageTypePrivacyPolicy,
		},
		{
			"terms body",
			"By using our service, you agree to these terms of use.",
			PageTypeTermsOfService,
		},
		{
			"binding agreement",
			"This constitutes a binding agreement between you and Acme Corp.",
			PageTypeTermsOfService,
		},
		{
			"trust center body",
			"Our security certifications demonstrate our commitment.",
			PageTypeTrustCenter,
		},
		{
			"compliance program",
			"Our compliance program covers SOC 2, ISO 27001, and more.",
			PageTypeTrustCenter,
		},
		{
			"dpa body",
			"As a data processor, we process data on behalf of our customers.",
			PageTypeDPA,
		},
		{
			"scc body",
			"We rely on standard contractual clauses for international transfers.",
			PageTypeDPA,
		},
		{
			"soc2 body",
			"We maintain SOC 2 Type II certification.",
			PageTypeSOC2Report,
		},
		{
			"security body",
			"Our vulnerability disclosure program welcomes reports.",
			PageTypeSecurity,
		},
		{
			"bug bounty",
			"We run a bug bounty program for security researchers.",
			PageTypeSecurity,
		},
		{
			"subprocessors body",
			"Below is our sub-processor list with details.",
			PageTypeSubprocessors,
		},
		{
			"cookies body",
			"We use cookies to improve your experience.",
			PageTypeCookiePolicy,
		},
		{
			"gdpr body",
			"Under the General Data Protection Regulation, you have rights.",
			PageTypeGDPR,
		},
		{
			"data subject rights",
			"Your data subject rights include the right to access.",
			PageTypeGDPR,
		},
		{
			"no match",
			"Welcome to our website. We build great products.",
			"",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ClassifyPage("https://example.com/page", "Some Page", tc.body)
			if result != tc.expected {
				t.Errorf("ClassifyPage(_, _, %q...): expected %q, got %q", tc.body[:min(len(tc.body), 40)], tc.expected, result)
			}
		})
	}
}

func TestClassifyPage_PriorityOrder(t *testing.T) {
	// URL match should take priority over title/body
	result := ClassifyPage("https://example.com/privacy", "Terms of Service", "We use cookies")
	if result != PageTypePrivacyPolicy {
		t.Errorf("expected URL match to win: got %q", result)
	}

	// Earlier rules in the list take priority when matching at the same level (body)
	// Privacy body patterns are checked before cookie body patterns
	result = ClassifyPage("https://example.com/page", "Some Page", "This privacy policy describes how we collect personal data")
	if result != PageTypePrivacyPolicy {
		t.Errorf("expected privacy rule to win (first in rule order): got %q", result)
	}

	// URL match beats body match from a different rule
	result = ClassifyPage("https://example.com/cookies", "Some Page", "This privacy policy describes")
	if result != PageTypeCookiePolicy {
		t.Errorf("expected URL match on cookies to win: got %q", result)
	}
}

func TestClassifyPage_CaseInsensitive(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		title    string
		expected string
	}{
		{"uppercase URL", "https://example.com/PRIVACY", "", PageTypePrivacyPolicy},
		{"mixed case title", "", "PRIVACY POLICY", PageTypePrivacyPolicy},
		{"lowercase gdpr title", "", "gdpr compliance", PageTypeGDPR},
		{"mixed case terms", "", "TERMS OF SERVICE", PageTypeTermsOfService},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := ClassifyPage(tc.url, tc.title, "")
			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}

func TestClassifyPage_EmptyInputs(t *testing.T) {
	result := ClassifyPage("", "", "")
	if result != "" {
		t.Errorf("expected empty result for empty inputs, got %q", result)
	}
}
