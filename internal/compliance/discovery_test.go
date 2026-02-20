package compliance

import (
	"context"
	"net/url"
	"testing"
)

func TestExtractLinksFromHTML(t *testing.T) {
	html := `
	<html>
	<body>
		<nav>
			<a href="/about">About</a>
			<a href="/privacy">Privacy Policy</a>
			<a href="/terms">Terms of Service</a>
			<a href="/blog">Blog</a>
		</nav>
		<footer>
			<a href="/legal/dpa">Data Processing Agreement</a>
			<a href="/trust-center">Trust Center</a>
			<a href="/careers">Careers</a>
			<a href="https://other.com/privacy">External Privacy</a>
			<a href="/security">Security</a>
			<a href="#section">Anchor</a>
		</footer>
	</body>
	</html>`

	links := extractLinksFromHTML(html, "example.com")

	expected := map[string]bool{
		"https://example.com/privacy":      true,
		"https://example.com/terms":        true,
		"https://example.com/legal/dpa":    true,
		"https://example.com/trust-center": true,
		"https://example.com/security":     true,
	}

	if len(links) != len(expected) {
		t.Fatalf("expected %d links, got %d: %v", len(expected), len(links), links)
	}

	for _, link := range links {
		if !expected[link] {
			t.Errorf("unexpected link: %s", link)
		}
	}
}

func TestExtractLinksFromHTML_FiltersNonCompliance(t *testing.T) {
	html := `
	<html><body>
		<a href="/about">About</a>
		<a href="/careers">Careers</a>
		<a href="/blog">Blog</a>
		<a href="/pricing">Pricing</a>
	</body></html>`

	links := extractLinksFromHTML(html, "example.com")

	if len(links) != 0 {
		t.Errorf("expected 0 compliance links, got %d: %v", len(links), links)
	}
}

func TestExtractLinksFromHTML_Deduplicates(t *testing.T) {
	html := `
	<html><body>
		<a href="/privacy">Privacy</a>
		<a href="/privacy">Privacy Policy</a>
		<a href="/privacy">Our Privacy</a>
	</body></html>`

	links := extractLinksFromHTML(html, "example.com")

	if len(links) != 1 {
		t.Errorf("expected 1 deduplicated link, got %d: %v", len(links), links)
	}
}

func TestExtractLinksFromHTML_FiltersExternalDomains(t *testing.T) {
	html := `
	<html><body>
		<a href="https://other.com/privacy">Other Privacy</a>
		<a href="https://example.com/privacy">Our Privacy</a>
	</body></html>`

	links := extractLinksFromHTML(html, "example.com")

	if len(links) != 1 {
		t.Errorf("expected 1 link (same domain only), got %d: %v", len(links), links)
	}

	if len(links) > 0 && links[0] != "https://example.com/privacy" {
		t.Errorf("expected https://example.com/privacy, got %s", links[0])
	}
}

func TestExtractTitle(t *testing.T) {
	tests := []struct {
		name     string
		html     string
		expected string
	}{
		{
			"standard title",
			"<html><head><title>Privacy Policy</title></head></html>",
			"Privacy Policy",
		},
		{
			"title with whitespace",
			"<html><head><title>  Trust Center  </title></head></html>",
			"Trust Center",
		},
		{
			"no title",
			"<html><body>Hello</body></html>",
			"",
		},
		{
			"empty title",
			"<html><head><title></title></head></html>",
			"",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := extractTitle(tc.html)
			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}

func TestBuildSubdomainTargets_NonExistentDomain(t *testing.T) {
	// buildSubdomainTargets does DNS resolution, so non-existent subdomains
	// return an empty list. This verifies the DNS filter works correctly.
	ctx := context.Background()
	targets := buildSubdomainTargets(ctx, "this-domain-definitely-does-not-exist-12345.example")

	if len(targets) != 0 {
		t.Errorf("expected 0 resolved targets for non-existent domain, got %d: %v", len(targets), targets)
	}
}

func TestFilterComplianceSubdomains(t *testing.T) {
	subdomains := []string{
		"trust.example.com",
		"security.example.com",
		"admin.example.com",
		"api.example.com",
		"compliance.example.com",
		"legal.example.com",
		"privacy.example.com",
		"status.example.com",
		"blog.example.com",
		"gdpr.example.com",
		"subprocessor.example.com",
	}

	targets := filterComplianceSubdomains(subdomains)

	expected := map[string]bool{
		"https://trust.example.com":          false,
		"https://security.example.com":       false,
		"https://compliance.example.com":     false,
		"https://legal.example.com":          false,
		"https://privacy.example.com":        false,
		"https://status.example.com":         false,
		"https://gdpr.example.com":           false,
		"https://subprocessor.example.com":   false,
	}

	if len(targets) != len(expected) {
		t.Fatalf("expected %d compliance subdomains, got %d: %v", len(expected), len(targets), targets)
	}

	for _, target := range targets {
		if _, ok := expected[target]; !ok {
			t.Errorf("unexpected target: %s", target)
		}

		expected[target] = true
	}

	for sub, found := range expected {
		if !found {
			t.Errorf("expected compliance subdomain %s not found", sub)
		}
	}
}

func TestFilterComplianceSubdomains_ExcludesNonCompliance(t *testing.T) {
	subdomains := []string{
		"admin.example.com",
		"api.example.com",
		"blog.example.com",
		"cdn.example.com",
		"mail.example.com",
	}

	targets := filterComplianceSubdomains(subdomains)

	if len(targets) != 0 {
		t.Errorf("expected 0 compliance subdomains, got %d: %v", len(targets), targets)
	}
}

func TestFilterComplianceSubdomains_CaseInsensitive(t *testing.T) {
	subdomains := []string{
		"Trust.example.com",
		"SECURITY.example.com",
	}

	targets := filterComplianceSubdomains(subdomains)

	if len(targets) != 2 {
		t.Fatalf("expected 2 case-insensitive matches, got %d: %v", len(targets), targets)
	}
}

func TestBuildPathTargets(t *testing.T) {
	homepageLinks := []string{
		"https://example.com/privacy",
		"https://example.com/trust-center",
		"https://example.com/custom-compliance",
	}

	targets := buildPathTargets(homepageLinks, "example.com", nil)

	// Should include homepage links + supplementary paths, deduplicated
	if len(targets) < len(homepageLinks) {
		t.Errorf("expected at least %d targets, got %d", len(homepageLinks), len(targets))
	}

	// First targets should be the homepage links (higher priority)
	for i, link := range homepageLinks {
		if i >= len(targets) {
			break
		}

		if targets[i] != link {
			t.Errorf("expected target %d to be %s, got %s", i, link, targets[i])
		}
	}

	// Verify deduplication: /privacy should appear only once
	count := 0

	for _, t2 := range targets {
		if t2 == "https://example.com/privacy" {
			count++
		}
	}

	if count != 1 {
		t.Errorf("expected /privacy to appear once, appeared %d times", count)
	}
}

func TestBuildPathTargets_EmptyHomepage(t *testing.T) {
	targets := buildPathTargets(nil, "example.com", nil)

	if len(targets) != len(supplementaryPaths) {
		t.Errorf("expected %d path targets, got %d", len(supplementaryPaths), len(targets))
	}
}

func TestBuildPathTargets_ExcludesExisting(t *testing.T) {
	exclude := map[string]struct{}{
		"https://trust.example.com":         {},
		"https://example.com/privacy":       {},
		"https://example.com/privacy-policy": {},
	}

	targets := buildPathTargets(nil, "example.com", exclude)

	for _, t2 := range targets {
		if _, excluded := exclude[t2]; excluded {
			t.Errorf("target %s should have been excluded", t2)
		}
	}
}

func TestPreferSubdomainPages(t *testing.T) {
	pages := []ClassifiedPage{
		{URL: "https://example.com/trust", PageType: PageTypeTrustCenter, Title: "Products - Trust"},
		{URL: "https://trust.example.com/", PageType: PageTypeTrustCenter, Title: "Trust Center"},
		{URL: "https://example.com/privacy", PageType: PageTypePrivacyPolicy, Title: "Privacy Policy"},
		{URL: "https://example.com/security", PageType: PageTypeSecurity, Title: "Security"},
	}

	result := PreferSubdomainPages(pages, "example.com")

	// Trust center should only have the subdomain entry
	trustCount := 0
	for _, p := range result {
		if p.PageType == PageTypeTrustCenter {
			trustCount++
			if p.URL != "https://trust.example.com/" {
				t.Errorf("expected subdomain trust center URL, got %s", p.URL)
			}
		}
	}

	if trustCount != 1 {
		t.Errorf("expected 1 trust center entry, got %d", trustCount)
	}

	// Privacy and security should remain (no subdomain competition)
	if len(result) != 3 {
		t.Errorf("expected 3 pages after dedup, got %d", len(result))
	}
}

func TestPreferSubdomainPages_NoSubdomain(t *testing.T) {
	pages := []ClassifiedPage{
		{URL: "https://example.com/trust", PageType: PageTypeTrustCenter, Title: "Trust Center"},
		{URL: "https://example.com/privacy", PageType: PageTypePrivacyPolicy, Title: "Privacy Policy"},
	}

	result := PreferSubdomainPages(pages, "example.com")

	if len(result) != 2 {
		t.Errorf("expected 2 pages (no subdomain competition), got %d", len(result))
	}
}

func TestPreferSubdomainPages_MultipleSubdomains(t *testing.T) {
	pages := []ClassifiedPage{
		{URL: "https://trust.example.com/", PageType: PageTypeTrustCenter, Title: "Trust Center"},
		{URL: "https://example.com/trust", PageType: PageTypeTrustCenter, Title: "Products"},
		{URL: "https://security.example.com/", PageType: PageTypeSecurity, Title: "Security Hub"},
		{URL: "https://example.com/security", PageType: PageTypeSecurity, Title: "Security Page"},
	}

	result := PreferSubdomainPages(pages, "example.com")

	if len(result) != 2 {
		t.Errorf("expected 2 pages (subdomains preferred), got %d", len(result))
	}

	for _, p := range result {
		parsed, _ := url.Parse(p.URL)
		if parsed.Hostname() == "example.com" {
			t.Errorf("expected subdomain URL, got root domain: %s", p.URL)
		}
	}
}

func TestNormalizeURL(t *testing.T) {
	tests := []struct {
		name     string
		rawURL   string
		domain   string
		expected string
	}{
		{"relative path", "/privacy", "example.com", "https://example.com/privacy"},
		{"absolute URL", "https://example.com/trust", "example.com", "https://example.com/trust"},
		{"whitespace", "  /legal/dpa  ", "example.com", "https://example.com/legal/dpa"},
		{"no scheme", "example.com/privacy", "example.com", "https://example.com/example.com/privacy"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := NormalizeURL(tc.rawURL, tc.domain)
			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}

func TestIsSameDomain(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		domain   string
		expected bool
	}{
		{"exact match", "https://example.com/privacy", "example.com", true},
		{"subdomain", "https://www.example.com/privacy", "example.com", true},
		{"different domain", "https://other.com/privacy", "example.com", false},
		{"partial match", "https://notexample.com/privacy", "example.com", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := isSameDomain(tc.url, tc.domain)
			if result != tc.expected {
				t.Errorf("expected %v, got %v", tc.expected, result)
			}
		})
	}
}

func TestExtractAllInternalLinks(t *testing.T) {
	html := `
	<html><body>
		<a href="/about">About</a>
		<a href="/privacy">Privacy</a>
		<a href="/careers">Careers</a>
		<a href="/blog">Blog</a>
		<a href="/soc2-report">SOC2</a>
		<a href="https://other.com/page">External</a>
		<a href="#anchor">Anchor</a>
	</body></html>`

	links := extractAllInternalLinks(html, "example.com")

	// Should include ALL same-domain links (about, privacy, careers, blog, soc2-report)
	// but NOT external links or anchors
	expected := map[string]bool{
		"https://example.com/about":       false,
		"https://example.com/privacy":     false,
		"https://example.com/careers":     false,
		"https://example.com/blog":        false,
		"https://example.com/soc2-report": false,
	}

	if len(links) != len(expected) {
		t.Fatalf("expected %d links, got %d: %v", len(expected), len(links), links)
	}

	for _, link := range links {
		if _, ok := expected[link]; !ok {
			t.Errorf("unexpected link: %s", link)
		}

		expected[link] = true
	}

	for link, found := range expected {
		if !found {
			t.Errorf("expected link not found: %s", link)
		}
	}
}

func TestExtractAllInternalLinks_Deduplicates(t *testing.T) {
	html := `
	<html><body>
		<a href="/about">About</a>
		<a href="/about">About Us</a>
		<a href="/about">About Page</a>
	</body></html>`

	links := extractAllInternalLinks(html, "example.com")

	if len(links) != 1 {
		t.Errorf("expected 1 deduplicated link, got %d: %v", len(links), links)
	}
}

func TestExtractAllInternalLinks_IncludesSubdomainLinks(t *testing.T) {
	html := `
	<html><body>
		<a href="https://sub.example.com/page">Sub Page</a>
		<a href="https://other.com/page">External</a>
	</body></html>`

	links := extractAllInternalLinks(html, "example.com")

	if len(links) != 1 {
		t.Errorf("expected 1 link (subdomain only), got %d: %v", len(links), links)
	}

	if len(links) > 0 && links[0] != "https://sub.example.com/page" {
		t.Errorf("expected subdomain link, got %s", links[0])
	}
}

func TestExtractAllInternalLinks_NoComplianceFilter(t *testing.T) {
	// Verify that non-compliance links ARE included (unlike extractLinksFromHTML)
	html := `
	<html><body>
		<a href="/about">About</a>
		<a href="/pricing">Pricing</a>
		<a href="/contact">Contact</a>
	</body></html>`

	allLinks := extractAllInternalLinks(html, "example.com")
	complianceLinks := extractLinksFromHTML(html, "example.com")

	if len(allLinks) != 3 {
		t.Errorf("extractAllInternalLinks: expected 3 links, got %d", len(allLinks))
	}

	if len(complianceLinks) != 0 {
		t.Errorf("extractLinksFromHTML: expected 0 compliance links, got %d", len(complianceLinks))
	}
}

func TestDeepCrawlablePageTypes(t *testing.T) {
	if _, ok := deepCrawlablePageTypes[PageTypeTrustCenter]; !ok {
		t.Error("trust_center should be a deep crawlable page type")
	}

	if _, ok := deepCrawlablePageTypes[PageTypeSecurity]; !ok {
		t.Error("security should be a deep crawlable page type")
	}

	if _, ok := deepCrawlablePageTypes[PageTypePrivacyPolicy]; ok {
		t.Error("privacy_policy should not be a deep crawlable page type")
	}
}

func TestHTTPXDiscoverer_InvalidDomain(t *testing.T) {
	d := NewHTTPXDiscoverer()

	_, err := d.Discover(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty domain")
	}
}

func TestNewHTTPXDiscoverer_DefaultOptions(t *testing.T) {
	d := NewHTTPXDiscoverer()

	if d.options.probeTimeout != defaultProbeTimeout {
		t.Errorf("expected default timeout %v, got %v", defaultProbeTimeout, d.options.probeTimeout)
	}

	if d.options.maxTargets != defaultMaxTargets {
		t.Errorf("expected default max targets %d, got %d", defaultMaxTargets, d.options.maxTargets)
	}

	if d.options.probeThreads != defaultProbeThreads {
		t.Errorf("expected default threads %d, got %d", defaultProbeThreads, d.options.probeThreads)
	}
}

func TestNewHTTPXDiscoverer_WithOptions(t *testing.T) {
	d := NewHTTPXDiscoverer(
		WithProbeTimeout(30*defaultProbeTimeout),
		WithMaxTargets(100),
		WithProbeThreads(20),
	)

	if d.options.maxTargets != 100 {
		t.Errorf("expected max targets 100, got %d", d.options.maxTargets)
	}

	if d.options.probeThreads != 20 {
		t.Errorf("expected threads 20, got %d", d.options.probeThreads)
	}
}
