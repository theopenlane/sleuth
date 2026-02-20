package compliance

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAnalyzeTrustCenterContent_SOC2Detection(t *testing.T) {
	body := `<html><body>
		<h1>Trust Center</h1>
		<p>We maintain SOC 2 Type II certification and undergo annual audits.</p>
		<p>Our SOC 2 report is available upon request.</p>
	</body></html>`

	analysis := AnalyzeTrustCenterContent(body, "https://trust.example.com", "example.com")

	var found bool
	for _, p := range analysis.InferredPages {
		if p.PageType == PageTypeSOC2Report {
			found = true
			assert.Equal(t, "https://trust.example.com", p.URL)
			assert.Contains(t, p.Title, "SOC 2")
		}
	}

	assert.True(t, found, "expected SOC 2 page to be inferred")

	assert.Contains(t, analysis.Frameworks, "SOC 2")
}

func TestAnalyzeTrustCenterContent_SubprocessorDetection(t *testing.T) {
	body := `<html><body>
		<h1>Trust Center</h1>
		<p>View our list of sub-processors and third-party vendors.</p>
	</body></html>`

	analysis := AnalyzeTrustCenterContent(body, "https://trust.example.com", "example.com")

	var found bool
	for _, p := range analysis.InferredPages {
		if p.PageType == PageTypeSubprocessors {
			found = true
		}
	}

	assert.True(t, found, "expected subprocessors page to be inferred")
}

func TestAnalyzeTrustCenterContent_MultipleIndicators(t *testing.T) {
	body := `<html><body>
		<h1>Security & Compliance</h1>
		<p>We are SOC 2 Type II certified and ISO 27001 compliant.</p>
		<p>Our privacy policy governs all data processing.</p>
		<p>View our terms of service for more details.</p>
		<p>HIPAA compliance is maintained for healthcare customers.</p>
		<a href="https://external.com/privacy">Privacy</a>
	</body></html>`

	analysis := AnalyzeTrustCenterContent(body, "https://trust.example.com", "example.com")

	typeSet := make(map[string]bool)
	for _, p := range analysis.InferredPages {
		typeSet[p.PageType] = true
	}

	assert.True(t, typeSet[PageTypeSOC2Report], "expected SOC 2 detection")
	assert.True(t, typeSet[PageTypePrivacyPolicy], "expected privacy policy detection")
	assert.True(t, typeSet[PageTypeTermsOfService], "expected terms of service detection")

	assert.Contains(t, analysis.Frameworks, "SOC 2")
	assert.Contains(t, analysis.Frameworks, "ISO 27001")
	assert.Contains(t, analysis.Frameworks, "HIPAA")
}

func TestAnalyzeTrustCenterContent_ExternalLinks(t *testing.T) {
	body := `<html><body>
		<a href="https://external-vendor.com/privacy-policy">Privacy Policy</a>
		<a href="https://external-vendor.com/terms">Terms</a>
		<a href="https://example.com/internal">Internal Link</a>
		<a href="#anchor">Anchor</a>
	</body></html>`

	analysis := AnalyzeTrustCenterContent(body, "https://trust.example.com", "example.com")

	require.Len(t, analysis.ExternalLinks, 2)
	assert.Contains(t, analysis.ExternalLinks[0], "external-vendor.com")
}

func TestAnalyzeTrustCenterContent_NoMatches(t *testing.T) {
	body := `<html><body><h1>Welcome</h1><p>Nothing compliance-related here.</p></body></html>`

	analysis := AnalyzeTrustCenterContent(body, "https://trust.example.com", "example.com")

	assert.Empty(t, analysis.InferredPages)
	assert.Empty(t, analysis.Frameworks)
	assert.Empty(t, analysis.ExternalLinks)
}

func TestAnalyzeTrustCenterContent_FrameworkDetection(t *testing.T) {
	body := `<html><body>
		<p>Certified: SOC 2 Type II, ISO 27001, PCI DSS, GDPR, CCPA, FedRAMP, CSA STAR</p>
	</body></html>`

	analysis := AnalyzeTrustCenterContent(body, "https://trust.example.com", "example.com")

	expected := []string{"SOC 2", "ISO 27001", "PCI DSS", "GDPR", "CCPA", "FedRAMP", "CSA STAR"}
	for _, f := range expected {
		assert.Contains(t, analysis.Frameworks, f, "expected framework: %s", f)
	}
}

func TestAnalyzeTrustCenterContent_NoDuplicatePageTypes(t *testing.T) {
	body := `<html><body>
		<p>SOC 2 Type II certified.</p>
		<p>Our SOC 2 report is available.</p>
		<p>We passed SOC 2 audits.</p>
	</body></html>`

	analysis := AnalyzeTrustCenterContent(body, "https://trust.example.com", "example.com")

	soc2Count := 0
	for _, p := range analysis.InferredPages {
		if p.PageType == PageTypeSOC2Report {
			soc2Count++
		}
	}

	assert.Equal(t, 1, soc2Count, "expected exactly one SOC 2 inferred page")
}

func TestPageTypeLabel(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{PageTypePrivacyPolicy, "Privacy Policy"},
		{PageTypeSOC2Report, "SOC 2"},
		{PageTypeTrustCenter, "Trust Center"},
		{"unknown_type", "unknown_type"},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.expected, pageTypeLabel(tt.input))
	}
}

func TestAnalyzeTrustCenterContent_IgnoresMetaTags(t *testing.T) {
	// Drata and similar platforms embed compliance keywords in meta tags
	// for ALL customers regardless of actual certifications
	body := `<html><head>
		<meta name="keywords" content="Drata,SOC 2,SOC2,ISO 27001,HIPAA,Pen Test"/>
		<meta name="description" content="Sign in to your trust center"/>
	</head><body>
		<h1>Welcome to our Trust Center</h1>
		<p>Contact us for more information.</p>
	</body></html>`

	analysis := AnalyzeTrustCenterContent(body, "https://trust.example.com", "example.com")

	// Should NOT detect SOC 2 or ISO 27001 from meta tags alone
	assert.Empty(t, analysis.InferredPages, "meta tag content should not produce inferred pages")
	assert.Empty(t, analysis.Frameworks, "meta tag content should not produce frameworks")
}

func TestAnalyzeTrustCenterContent_AspirationalSOC2(t *testing.T) {
	// "preparing to get our SOC 2" should NOT trigger SOC 2 detection
	body := `<html><body>
		<h1>Trust Center</h1>
		<p>We are currently preparing to get our SOC 2 certification.</p>
		<p>We expect to complete the audit next quarter.</p>
	</body></html>`

	analysis := AnalyzeTrustCenterContent(body, "https://trust.example.com", "example.com")

	for _, p := range analysis.InferredPages {
		assert.NotEqual(t, PageTypeSOC2Report, p.PageType, "aspirational SOC 2 should not produce inferred page")
	}

	assert.NotContains(t, analysis.Frameworks, "SOC 2", "aspirational SOC 2 should not produce framework")
}

func TestAnalyzeTrustCenterContent_AspirationalISO27001(t *testing.T) {
	body := `<html><body>
		<h1>Security</h1>
		<p>We are pursuing ISO 27001 certification and working toward HIPAA compliance.</p>
	</body></html>`

	analysis := AnalyzeTrustCenterContent(body, "https://trust.example.com", "example.com")

	assert.NotContains(t, analysis.Frameworks, "ISO 27001", "pursuing ISO 27001 should not produce framework")
	assert.NotContains(t, analysis.Frameworks, "HIPAA", "working toward HIPAA should not produce framework")
}

func TestAnalyzeTrustCenterContent_MixedAchievedAndAspirations(t *testing.T) {
	// SOC 2 is achieved, ISO 27001 is aspirational — only SOC 2 should be detected
	body := `<html><body>
		<h1>Trust Center</h1>
		<p>We are SOC 2 Type II certified and undergo annual audits.</p>
		<p>We are currently evaluating ISO 27001 certification.</p>
	</body></html>`

	analysis := AnalyzeTrustCenterContent(body, "https://trust.example.com", "example.com")

	assert.Contains(t, analysis.Frameworks, "SOC 2", "achieved SOC 2 should be detected")
	assert.NotContains(t, analysis.Frameworks, "ISO 27001", "evaluating ISO 27001 should not be detected")
}

func TestMatchesAffirmatively(t *testing.T) {
	soc2Pattern := compileAll(`(?i)\bsoc\s*2\b`)

	tests := []struct {
		name     string
		text     string
		expected bool
	}{
		{"achieved", "We are SOC 2 Type II certified.", true},
		{"preparing", "We are preparing to get our SOC 2 certification.", false},
		{"pursuing", "Currently pursuing SOC 2 compliance.", false},
		{"roadmap", "SOC 2 is on our roadmap for next year.", false},
		{"planning", "We are planning our SOC 2 audit.", false},
		{"no match", "We have strong security practices.", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchesAffirmatively(soc2Pattern, tt.text)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractExternalComplianceLinks(t *testing.T) {
	body := `<html><body>
		<a href="https://vendor.com/privacy-policy">Privacy</a>
		<a href="https://vendor.com/about">About</a>
		<a href="https://example.com/privacy">Internal</a>
		<a href="https://sub.example.com/terms">Sub Internal</a>
		<a href="/relative">Relative</a>
		<a href="#">Hash</a>
		<a href="javascript:void(0)">JS</a>
	</body></html>`

	links := extractExternalComplianceLinks(body, "example.com")

	require.Len(t, links, 1)
	assert.Equal(t, "https://vendor.com/privacy-policy", links[0])
}
