package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/theopenlane/sleuth/internal/cloudflare"
	"github.com/theopenlane/sleuth/internal/compliance"
	"github.com/theopenlane/sleuth/internal/slack"
)

// mockDiscoverer implements compliance.Discoverer for testing
type mockDiscoverer struct {
	pages []compliance.ClassifiedPage
	err   error
}

func (m *mockDiscoverer) Discover(_ context.Context, _ string) ([]compliance.ClassifiedPage, error) {
	return m.pages, m.err
}

func TestHandleComplianceDiscovery_NotConfigured(t *testing.T) {
	handler := &Handler{
		scanner:     NewMockScanner(false, 0),
		discoverer:  nil,
		maxBodySize: 1024,
	}

	body, _ := json.Marshal(ComplianceRequest{Domain: "example.com"})
	req := httptest.NewRequest(http.MethodPost, "/api/compliance", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.handleComplianceDiscovery(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status 503, got %d", w.Code)
	}
}

func TestHandleComplianceDiscovery_MissingDomain(t *testing.T) {
	handler := &Handler{
		scanner:     NewMockScanner(false, 0),
		discoverer:  &mockDiscoverer{},
		maxBodySize: 1024,
	}

	body, _ := json.Marshal(ComplianceRequest{})
	req := httptest.NewRequest(http.MethodPost, "/api/compliance", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.handleComplianceDiscovery(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
}

func TestHandleComplianceDiscovery_DiscoveryError(t *testing.T) {
	handler := &Handler{
		scanner:     NewMockScanner(false, 0),
		discoverer:  &mockDiscoverer{err: errors.New("discovery failed")},
		maxBodySize: 1024,
	}

	body, _ := json.Marshal(ComplianceRequest{Domain: "example.com"})
	req := httptest.NewRequest(http.MethodPost, "/api/compliance", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.handleComplianceDiscovery(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("expected status 502, got %d", w.Code)
	}
}

func TestHandleComplianceDiscovery_WithoutEnricher(t *testing.T) {
	discoverer := &mockDiscoverer{
		pages: []compliance.ClassifiedPage{
			{URL: "https://example.com/privacy", Title: "Privacy Policy", PageType: compliance.PageTypePrivacyPolicy, StatusCode: 200},
			{URL: "https://example.com/terms", Title: "Terms of Service", PageType: compliance.PageTypeTermsOfService, StatusCode: 200},
		},
	}

	handler := &Handler{
		scanner:     NewMockScanner(false, 0),
		discoverer:  discoverer,
		enricher:    nil,
		maxBodySize: 1024,
	}

	body, _ := json.Marshal(ComplianceRequest{Domain: "example.com"})
	req := httptest.NewRequest(http.MethodPost, "/api/compliance", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.handleComplianceDiscovery(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var resp ComplianceResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !resp.Success {
		t.Error("expected success=true")
	}

	if resp.Data == nil {
		t.Fatal("expected data to be non-nil")
	}

	if resp.Data.Domain != "example.com" {
		t.Errorf("expected domain example.com, got %s", resp.Data.Domain)
	}

	if len(resp.Data.Pages) != 2 {
		t.Fatalf("expected 2 pages, got %d", len(resp.Data.Pages))
	}

	if !resp.Data.Summary.HasPrivacyPolicy {
		t.Error("expected HasPrivacyPolicy=true")
	}

	if !resp.Data.Summary.HasTermsOfService {
		t.Error("expected HasTermsOfService=true")
	}
}

func TestHandleComplianceDiscovery_WithEnricher(t *testing.T) {
	discoverer := &mockDiscoverer{
		pages: []compliance.ClassifiedPage{
			{URL: "https://trust.example.com", Title: "Trust Center", PageType: compliance.PageTypeTrustCenter, StatusCode: 200},
			{URL: "https://example.com/privacy", Title: "Privacy Policy", PageType: compliance.PageTypePrivacyPolicy, StatusCode: 200},
		},
	}

	expectedPage := cloudflare.CompliancePage{
		PageType:      "trust_center",
		Title:         "Trust Center",
		Summary:       "Our security certifications.",
		Frameworks:    []string{"SOC 2 Type II"},
		Subprocessors: []string{"AWS", "Stripe"},
	}

	cfServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		type pageResponse struct {
			Success bool                     `json:"success"`
			Result  cloudflare.CompliancePage `json:"result"`
		}

		if err := json.NewEncoder(w).Encode(pageResponse{
			Success: true,
			Result:  expectedPage,
		}); err != nil {
			t.Errorf("failed to encode mock page response: %v", err)
		}
	}))
	defer cfServer.Close()

	enricher, err := cloudflare.New("test-account", "test-token",
		cloudflare.WithHTTPClient(cfServer.Client()),
		cloudflare.WithBaseURL(cfServer.URL),
	)
	if err != nil {
		t.Fatalf("unexpected error creating enricher: %v", err)
	}

	handler := &Handler{
		scanner:     NewMockScanner(false, 0),
		discoverer:  discoverer,
		enricher:    enricher,
		maxBodySize: 1024,
	}

	body, _ := json.Marshal(ComplianceRequest{Domain: "example.com"})
	req := httptest.NewRequest(http.MethodPost, "/api/compliance", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.handleComplianceDiscovery(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var resp ComplianceResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !resp.Success {
		t.Error("expected success=true")
	}

	if resp.Data == nil {
		t.Fatal("expected data to be non-nil")
	}

	if resp.Data.Domain != "example.com" {
		t.Errorf("expected domain example.com, got %s", resp.Data.Domain)
	}

	// Should have 2 pages: trust_center from CF AI + privacy_policy passthrough
	if len(resp.Data.Pages) != 2 {
		t.Errorf("expected 2 pages, got %d", len(resp.Data.Pages))
	}

	// Subprocessors should be aggregated into summary
	if len(resp.Data.Summary.Subprocessors) != 2 {
		t.Errorf("expected 2 subprocessors, got %d: %v", len(resp.Data.Summary.Subprocessors), resp.Data.Summary.Subprocessors)
	}
}

func TestHandleComplianceDiscovery_WithSlack(t *testing.T) {
	discoverer := &mockDiscoverer{
		pages: []compliance.ClassifiedPage{
			{URL: "https://example.com/privacy", Title: "Privacy Policy", PageType: compliance.PageTypePrivacyPolicy, StatusCode: 200},
		},
	}

	slackReceived := false
	slackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		slackReceived = true
		w.WriteHeader(http.StatusOK)
	}))
	defer slackServer.Close()

	notifier, err := slack.New(slackServer.URL, slack.WithHTTPClient(slackServer.Client()))
	if err != nil {
		t.Fatalf("unexpected error creating notifier: %v", err)
	}

	handler := &Handler{
		scanner:     NewMockScanner(false, 0),
		discoverer:  discoverer,
		notifier:    notifier,
		maxBodySize: 1024,
	}

	body, _ := json.Marshal(ComplianceRequest{Domain: "example.com"})
	req := httptest.NewRequest(http.MethodPost, "/api/compliance", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.handleComplianceDiscovery(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var resp ComplianceResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !resp.Data.SlackNotified {
		t.Error("expected slack_notified=true")
	}

	if !slackReceived {
		t.Error("expected Slack webhook to be called")
	}
}

func TestHandleComplianceDiscovery_EmailExtraction(t *testing.T) {
	discoverer := &mockDiscoverer{
		pages: []compliance.ClassifiedPage{
			{URL: "https://example.com/privacy", Title: "Privacy Policy", PageType: compliance.PageTypePrivacyPolicy, StatusCode: 200},
		},
	}

	handler := &Handler{
		scanner:     NewMockScanner(false, 0),
		discoverer:  discoverer,
		maxBodySize: 1024,
	}

	body, _ := json.Marshal(ComplianceRequest{Email: "user@example.com"})
	req := httptest.NewRequest(http.MethodPost, "/api/compliance", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.handleComplianceDiscovery(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var resp ComplianceResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Data.Email != "user@example.com" {
		t.Errorf("expected email user@example.com, got %s", resp.Data.Email)
	}

	if resp.Data.Domain != "example.com" {
		t.Errorf("expected domain example.com, got %s", resp.Data.Domain)
	}
}

func TestBuildComplianceSummary(t *testing.T) {
	pages := []cloudflare.CompliancePage{
		{
			PageType:      "privacy_policy",
			Title:         "Privacy Policy",
			Frameworks:    []string{"GDPR", "CCPA"},
			DownloadLinks: []string{"https://example.com/privacy.pdf"},
		},
		{
			PageType:   "trust_center",
			Title:      "Trust Center",
			Frameworks: []string{"SOC 2 Type II", "ISO 27001", "GDPR"},
		},
		{
			PageType:      "soc2_report",
			Title:         "SOC 2 Report",
			Frameworks:    []string{"SOC 2 Type II"},
			DownloadLinks: []string{"https://example.com/soc2.pdf", "https://example.com/privacy.pdf"},
		},
		{
			PageType:   "terms_of_service",
			Title:      "Terms of Service",
			Frameworks: nil,
		},
		{
			PageType: "dpa",
			Title:    "Data Processing Agreement",
		},
		{
			PageType: "security",
			Title:    "Security",
		},
		{
			PageType: "subprocessors",
			Title:    "Subprocessors",
		},
		{
			PageType: "cookie_policy",
			Title:    "Cookie Policy",
		},
		{
			PageType: "gdpr",
			Title:    "GDPR Rights",
		},
	}

	summary := buildComplianceSummary(pages)

	if !summary.HasPrivacyPolicy {
		t.Error("expected HasPrivacyPolicy=true")
	}

	if !summary.HasTrustCenter {
		t.Error("expected HasTrustCenter=true")
	}

	if !summary.HasSOC2 {
		t.Error("expected HasSOC2=true")
	}

	if !summary.HasTermsOfService {
		t.Error("expected HasTermsOfService=true")
	}

	if !summary.HasDPA {
		t.Error("expected HasDPA=true")
	}

	if !summary.HasSecurityPage {
		t.Error("expected HasSecurityPage=true")
	}

	if !summary.HasSubprocessors {
		t.Error("expected HasSubprocessors=true")
	}

	if !summary.HasCookiePolicy {
		t.Error("expected HasCookiePolicy=true")
	}

	if !summary.HasGDPR {
		t.Error("expected HasGDPR=true")
	}

	// PageCount should equal total pages
	if summary.PageCount != len(pages) {
		t.Errorf("expected PageCount=%d, got %d", len(pages), summary.PageCount)
	}

	// GDPR, CCPA, SOC 2 Type II, ISO 27001 = 4 unique frameworks
	if len(summary.Frameworks) != 4 {
		t.Errorf("expected 4 unique frameworks, got %d: %v", len(summary.Frameworks), summary.Frameworks)
	}

	frameworkSet := make(map[string]bool)
	for _, f := range summary.Frameworks {
		frameworkSet[f] = true
	}

	for _, expected := range []string{"GDPR", "CCPA", "SOC 2 Type II", "ISO 27001"} {
		if !frameworkSet[expected] {
			t.Errorf("expected framework %s in summary", expected)
		}
	}

	// Frameworks should be sorted
	for i := 1; i < len(summary.Frameworks); i++ {
		if summary.Frameworks[i] < summary.Frameworks[i-1] {
			t.Errorf("expected frameworks to be sorted, got %v", summary.Frameworks)
			break
		}
	}

	// Download links should be deduplicated (3 total, 1 duplicate = 2 unique)
	if len(summary.DownloadLinks) != 2 {
		t.Errorf("expected 2 unique download links, got %d: %v", len(summary.DownloadLinks), summary.DownloadLinks)
	}
}

func TestBuildComplianceSummary_FrameworkFlags(t *testing.T) {
	pages := []cloudflare.CompliancePage{
		{
			PageType:   "trust_center",
			Title:      "Trust Center",
			Frameworks: []string{"SOC 2 Type II", "ISO 27001", "HIPAA", "PCI DSS", "FedRAMP", "GDPR", "CCPA"},
		},
	}

	summary := buildComplianceSummary(pages)

	if !summary.HasISO27001 {
		t.Error("expected HasISO27001=true")
	}

	if !summary.HasHIPAA {
		t.Error("expected HasHIPAA=true")
	}

	if !summary.HasPCIDSS {
		t.Error("expected HasPCIDSS=true")
	}

	if !summary.HasSOC2Framework {
		t.Error("expected HasSOC2Framework=true")
	}

	if !summary.HasGDPRFramework {
		t.Error("expected HasGDPRFramework=true")
	}

	if !summary.HasCCPA {
		t.Error("expected HasCCPA=true")
	}

	if !summary.HasFedRAMP {
		t.Error("expected HasFedRAMP=true")
	}
}

func TestBuildComplianceSummary_NoFrameworkFlags(t *testing.T) {
	pages := []cloudflare.CompliancePage{
		{
			PageType: "privacy_policy",
			Title:    "Privacy Policy",
		},
	}

	summary := buildComplianceSummary(pages)

	if summary.HasISO27001 || summary.HasHIPAA || summary.HasPCIDSS || summary.HasSOC2Framework || summary.HasGDPRFramework || summary.HasCCPA || summary.HasFedRAMP {
		t.Error("expected no framework flags to be set when no frameworks are present")
	}

	if summary.PageCount != 1 {
		t.Errorf("expected PageCount=1, got %d", summary.PageCount)
	}
}

func TestBuildComplianceSlackMessage(t *testing.T) {
	summary := ComplianceSummary{
		HasPrivacyPolicy:  true,
		HasTrustCenter:    true,
		HasSOC2:           true,
		HasTermsOfService: true,
		Frameworks:        []string{"SOC 2 Type II", "GDPR"},
	}

	pages := []cloudflare.CompliancePage{
		{URL: "https://example.com/privacy", Title: "Privacy Policy", Summary: "Our privacy practices."},
		{URL: "https://example.com/trust", Title: "Trust Center", Summary: "Our certifications."},
	}

	msg := buildComplianceSlackMessage("example.com", "user@example.com", summary, pages)

	if msg.Text == "" {
		t.Error("expected fallback text to be set")
	}

	if len(msg.Blocks) == 0 {
		t.Fatal("expected blocks to be populated")
	}

	if msg.Blocks[0].Type != "header" {
		t.Errorf("expected first block to be header, got %s", msg.Blocks[0].Type)
	}
}

func TestSplitByEnrichability(t *testing.T) {
	pages := []compliance.ClassifiedPage{
		{URL: "https://trust.example.com", PageType: compliance.PageTypeTrustCenter},
		{URL: "https://example.com/privacy", PageType: compliance.PageTypePrivacyPolicy},
		{URL: "https://security.example.com", PageType: compliance.PageTypeSecurity},
		{URL: "https://example.com/terms", PageType: compliance.PageTypeTermsOfService},
		{URL: "https://example.com/sub-processors", PageType: compliance.PageTypeSubprocessors},
		{URL: "https://example.com/dpa", PageType: compliance.PageTypeDPA},
	}

	enrichable, passthrough := splitByEnrichability(pages)

	if len(enrichable) != 3 {
		t.Errorf("expected 3 enrichable pages, got %d", len(enrichable))
	}

	if len(passthrough) != 3 {
		t.Errorf("expected 3 passthrough pages, got %d", len(passthrough))
	}

	enrichableTypes := make(map[string]bool)
	for _, p := range enrichable {
		enrichableTypes[p.PageType] = true
	}

	if !enrichableTypes[compliance.PageTypeTrustCenter] {
		t.Error("expected trust_center in enrichable")
	}

	if !enrichableTypes[compliance.PageTypeSecurity] {
		t.Error("expected security in enrichable")
	}

	if !enrichableTypes[compliance.PageTypeSubprocessors] {
		t.Error("expected subprocessors in enrichable")
	}
}

func TestBuildComplianceSummary_Subprocessors(t *testing.T) {
	pages := []cloudflare.CompliancePage{
		{
			PageType:      "trust_center",
			Title:         "Trust Center",
			Subprocessors: []string{"AWS", "Google Cloud", "Stripe"},
		},
		{
			PageType:      "subprocessors",
			Title:         "Sub-processors",
			Subprocessors: []string{"Stripe", "Datadog", "Cloudflare"},
		},
	}

	summary := buildComplianceSummary(pages)

	if !summary.HasSubprocessors {
		t.Error("expected HasSubprocessors=true")
	}

	if len(summary.Subprocessors) != 5 {
		t.Errorf("expected 5 unique subprocessors, got %d: %v", len(summary.Subprocessors), summary.Subprocessors)
	}

	// Should be sorted
	for i := 1; i < len(summary.Subprocessors); i++ {
		if summary.Subprocessors[i] < summary.Subprocessors[i-1] {
			t.Errorf("expected subprocessors to be sorted, got %v", summary.Subprocessors)
			break
		}
	}
}

func TestClassifiedToCompliancePages(t *testing.T) {
	classified := []compliance.ClassifiedPage{
		{URL: "https://example.com/privacy", Title: "Privacy Policy", PageType: compliance.PageTypePrivacyPolicy, StatusCode: 200},
		{URL: "https://example.com/terms", Title: "Terms", PageType: compliance.PageTypeTermsOfService, StatusCode: 200},
	}

	pages := classifiedToCompliancePages(classified)

	if len(pages) != 2 {
		t.Fatalf("expected 2 pages, got %d", len(pages))
	}

	if pages[0].URL != "https://example.com/privacy" {
		t.Errorf("expected URL https://example.com/privacy, got %s", pages[0].URL)
	}

	if pages[0].PageType != compliance.PageTypePrivacyPolicy {
		t.Errorf("expected page type %s, got %s", compliance.PageTypePrivacyPolicy, pages[0].PageType)
	}

	if pages[1].Title != "Terms" {
		t.Errorf("expected title Terms, got %s", pages[1].Title)
	}
}
