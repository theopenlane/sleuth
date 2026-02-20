package api

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"github.com/samber/lo"

	"github.com/theopenlane/sleuth/internal/cloudflare"
	"github.com/theopenlane/sleuth/internal/compliance"
	"github.com/theopenlane/sleuth/internal/slack"
)

const (
	// maxCompliancePages caps the number of pages to analyze via Cloudflare AI
	maxCompliancePages = 15
)

// ComplianceRequest represents a compliance discovery request
type ComplianceRequest struct {
	// Domain is the domain to scan for compliance pages
	Domain string `json:"domain,omitempty"`
	// Email is the email address to extract domain from
	Email string `json:"email,omitempty"`
	// Subdomains is an optional list of pre-discovered subdomains to filter
	// for compliance-relevant pages. When provided, skips static subdomain
	// enumeration and uses these instead. Typically sourced from a prior scan.
	Subdomains []string `json:"subdomains,omitempty"`
	// NotifySlack controls whether to send a Slack notification. Defaults to true when omitted.
	NotifySlack *bool `json:"notify_slack,omitempty"`
}

// ComplianceResult holds the compliance discovery output
type ComplianceResult struct {
	// Domain is the domain that was scanned
	Domain string `json:"domain"`
	// Email is the email that triggered the scan, if provided
	Email string `json:"email,omitempty"`
	// Pages holds the analyzed compliance pages
	Pages []cloudflare.CompliancePage `json:"pages"`
	// Summary aggregates compliance posture from all discovered pages
	Summary ComplianceSummary `json:"summary"`
	// SlackNotified indicates whether a Slack notification was sent
	SlackNotified bool `json:"slack_notified"`
}

// ComplianceSummary provides a boolean snapshot of compliance coverage
type ComplianceSummary struct {
	// HasPrivacyPolicy indicates whether a privacy policy was found
	HasPrivacyPolicy bool `json:"has_privacy_policy"`
	// HasTermsOfService indicates whether terms of service were found
	HasTermsOfService bool `json:"has_terms_of_service"`
	// HasTrustCenter indicates whether a trust center page was found
	HasTrustCenter bool `json:"has_trust_center"`
	// HasDPA indicates whether a data processing agreement was found
	HasDPA bool `json:"has_dpa"`
	// HasSOC2 indicates whether a SOC 2 report page was found
	HasSOC2 bool `json:"has_soc2"`
	// HasSecurityPage indicates whether a security page was found
	HasSecurityPage bool `json:"has_security_page"`
	// HasSubprocessors indicates whether a subprocessor list was found
	HasSubprocessors bool `json:"has_subprocessors"`
	// HasCookiePolicy indicates whether a cookie policy was found
	HasCookiePolicy bool `json:"has_cookie_policy"`
	// HasGDPR indicates whether a GDPR-specific page was found
	HasGDPR bool `json:"has_gdpr"`
	// HasISO27001 indicates whether ISO 27001 certification was mentioned
	HasISO27001 bool `json:"has_iso27001"`
	// HasHIPAA indicates whether HIPAA compliance was mentioned
	HasHIPAA bool `json:"has_hipaa"`
	// HasPCIDSS indicates whether PCI DSS compliance was mentioned
	HasPCIDSS bool `json:"has_pci_dss"`
	// HasSOC2Framework indicates whether SOC 2 was mentioned as a framework
	HasSOC2Framework bool `json:"has_soc2_framework"`
	// HasGDPRFramework indicates whether GDPR was mentioned as a framework
	HasGDPRFramework bool `json:"has_gdpr_framework"`
	// HasCCPA indicates whether CCPA compliance was mentioned
	HasCCPA bool `json:"has_ccpa"`
	// HasFedRAMP indicates whether FedRAMP compliance was mentioned
	HasFedRAMP bool `json:"has_fedramp"`
	// Frameworks lists all unique compliance frameworks mentioned across pages
	Frameworks []string `json:"frameworks,omitempty"`
	// DownloadLinks aggregates downloadable document URLs found across all pages
	DownloadLinks []string `json:"download_links,omitempty"`
	// Subprocessors aggregates third-party vendor names found across all pages
	Subprocessors []string `json:"subprocessors,omitempty"`
	// PageCount is the total number of compliance pages discovered
	PageCount int `json:"page_count"`
}

// ComplianceResponse is the API response envelope for compliance discovery
type ComplianceResponse struct {
	// Success indicates whether the compliance discovery completed successfully
	Success bool `json:"success"`
	// Data holds the compliance result when successful
	Data *ComplianceResult `json:"data,omitempty"`
	// Error is the normalized error payload when discovery fails
	Error *Error `json:"error,omitempty"`
}

// handleComplianceDiscovery processes compliance page discovery requests
func (h *Handler) handleComplianceDiscovery(w http.ResponseWriter, r *http.Request) {
	if h.discoverer == nil {
		respondComplianceError(w, http.StatusServiceUnavailable, errCodeUnavailable, ErrComplianceDiscoveryFailed.Error())
		return
	}

	if h.maxBodySize > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, h.maxBodySize)
	}

	var req ComplianceRequest
	if err := decodeJSONBody(r, &req); err != nil {
		respondComplianceError(w, http.StatusBadRequest, errCodeInvalidRequest, ErrInvalidRequestBody.Error())
		return
	}

	domain := req.Domain

	if domain == "" && req.Email != "" {
		extracted, err := extractEmailDomain(req.Email)
		if err != nil {
			respondComplianceError(w, http.StatusBadRequest, errCodeValidation, err.Error())
			return
		}

		domain = extracted
	}

	if domain == "" {
		respondComplianceError(w, http.StatusBadRequest, errCodeValidation, ErrDomainRequired.Error())
		return
	}

	var (
		pages []cloudflare.CompliancePage
		err   error
	)

	// Use phased discovery when available to overlap CF AI with path probing.
	// Subdomains (~2s) are probed first; enrichable results start CF AI immediately
	// while homepage + path discovery runs concurrently (~5s overlapped with ~20s CF AI).
	phased, canPhase := h.discoverer.(compliance.PhasedDiscoverer)
	if canPhase && h.enricher != nil {
		pages, err = h.phasedComplianceDiscovery(r.Context(), phased, domain, req.Subdomains)
	} else {
		pages, err = h.sequentialComplianceDiscovery(r.Context(), domain)
	}

	if err != nil {
		log.Error().Err(err).Str("domain", domain).Msg("compliance discovery failed")
		respondComplianceError(w, http.StatusBadGateway, errCodeInternal, fmt.Sprintf("compliance discovery failed: %v", err))
		return
	}

	summary := buildComplianceSummary(pages)

	result := &ComplianceResult{
		Domain:  domain,
		Email:   req.Email,
		Pages:   pages,
		Summary: summary,
	}

	shouldNotify := req.NotifySlack == nil || *req.NotifySlack
	if shouldNotify && h.notifier != nil {
		msg := buildComplianceSlackMessage(domain, req.Email, summary, pages)

		if err := h.notifier.Send(r.Context(), msg); err != nil {
			log.Error().Err(err).Str("domain", domain).Msg("compliance slack notification failed")
		} else {
			result.SlackNotified = true
		}
	}

	writeJSON(w, http.StatusOK, ComplianceResponse{
		Success: true,
		Data:    result,
	})
}

// analyzeCompliancePages runs concurrent Cloudflare AI analysis on classified pages
func analyzeCompliancePages(ctx context.Context, enricher *cloudflare.Client, classified <-chan compliance.ClassifiedPage) []cloudflare.CompliancePage {
	var (
		mu    sync.Mutex
		pages []cloudflare.CompliancePage
		wg    sync.WaitGroup
	)

	for cp := range classified {
		wg.Add(1)

		go func(page compliance.ClassifiedPage) {
			defer wg.Done()

			if ctx.Err() != nil {
				return
			}

			analyzed := analyzeOnePage(ctx, enricher, page)

			mu.Lock()
			pages = append(pages, analyzed)
			mu.Unlock()
		}(cp)
	}

	wg.Wait()

	return pages
}

// analyzeCompliancePagesSlice is a convenience wrapper that feeds a slice into
// analyzeCompliancePages. Used by the sequential discovery path.
func analyzeCompliancePagesSlice(ctx context.Context, enricher *cloudflare.Client, classified []compliance.ClassifiedPage) []cloudflare.CompliancePage {
	return analyzeCompliancePages(ctx, enricher, lo.SliceToChannel(len(classified), classified))
}

// followComplianceLinks extracts compliance_links from analyzed pages (e.g., trust
// center sub-navigation), filters out already-analyzed URLs, and runs the new links
// through CF AI. This handles SPA trust centers where the landing page references
// sub-pages containing actual certifications (SOC2, ISO, etc.).
//
// Only links on the same host as the source page are followed to avoid crawling
// into documentation sites, product pages, or unrelated domains.
func followComplianceLinks(ctx context.Context, enricher *cloudflare.Client, pages []cloudflare.CompliancePage) []cloudflare.CompliancePage {
	analyzedURLs := make(map[string]struct{}, len(pages))
	for _, p := range pages {
		analyzedURLs[p.URL] = struct{}{}
	}

	// Build a map of source page hosts so we only follow same-host links
	pageHosts := make(map[string]struct{}, len(pages))
	for _, p := range pages {
		if u, err := parseURL(p.URL); err == nil {
			pageHosts[u.Host] = struct{}{}
		}
	}

	var followUp []compliance.ClassifiedPage

	for _, p := range pages {
		sourceHost := ""
		if u, err := parseURL(p.URL); err == nil {
			sourceHost = u.Host
		}

		for _, link := range p.ComplianceLinks {
			if _, exists := analyzedURLs[link]; exists {
				continue
			}

			linkURL, err := parseURL(link)
			if err != nil {
				continue
			}

			// Only follow links on the same host as the source page
			if linkURL.Host != sourceHost {
				continue
			}

			// Skip links that look like docs or product pages
			if isNonCompliancePath(linkURL.Path) {
				continue
			}

			analyzedURLs[link] = struct{}{}
			followUp = append(followUp, compliance.ClassifiedPage{
				URL:      link,
				PageType: compliance.PageTypeTrustCenter,
			})
		}
	}

	if len(followUp) == 0 {
		return nil
	}

	log.Info().Int("follow_up_links", len(followUp)).Msg("following compliance links from trust center")

	return analyzeCompliancePagesSlice(ctx, enricher, followUp)
}

// parseURL is a thin wrapper around net/url.Parse
func parseURL(rawURL string) (*url.URL, error) {
	return url.Parse(rawURL)
}

// nonCompliancePathPrefixes are URL path prefixes that indicate documentation,
// product, or marketing pages rather than actual compliance artifacts.
var nonCompliancePathPrefixes = []string{
	"/docs/",
	"/blog/",
	"/product/",
	"/company/",
	"/api/",
	"/changelog",
	"/pricing",
}

// isNonCompliancePath returns true if the URL path matches a known non-compliance prefix
func isNonCompliancePath(path string) bool {
	lower := strings.ToLower(path)
	for _, prefix := range nonCompliancePathPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}

	return false
}

// analyzeOnePage runs Cloudflare AI analysis on a single page, falling back to
// regex-classified data on error.
func analyzeOnePage(ctx context.Context, enricher *cloudflare.Client, page compliance.ClassifiedPage) cloudflare.CompliancePage {
	analyzed, err := enricher.AnalyzeCompliancePage(ctx, page.URL)
	if err != nil {
		log.Warn().Err(err).Str("url", page.URL).Msg("compliance page analysis failed")

		return cloudflare.CompliancePage{
			URL:        page.URL,
			PageType:   page.PageType,
			Title:      page.Title,
			Frameworks: page.Frameworks,
		}
	}

	log.Info().Str("url", page.URL).Str("page_type", analyzed.PageType).Str("title", analyzed.Title).Int("frameworks", len(analyzed.Frameworks)).Int("subprocessors", len(analyzed.Subprocessors)).Int("compliance_links", len(analyzed.ComplianceLinks)).Msg("cloudflare AI analysis result")

	// Preserve regex classification when AI returns empty values
	if analyzed.PageType == "" {
		analyzed.PageType = page.PageType
	}

	if analyzed.Title == "" {
		analyzed.Title = page.Title
	}

	// Merge frameworks from content analysis with AI-detected frameworks
	if len(page.Frameworks) > 0 {
		seen := make(map[string]struct{}, len(analyzed.Frameworks))
		for _, f := range analyzed.Frameworks {
			seen[f] = struct{}{}
		}

		for _, f := range page.Frameworks {
			if _, exists := seen[f]; !exists {
				analyzed.Frameworks = append(analyzed.Frameworks, f)
			}
		}
	}

	return analyzed
}

// phasedComplianceDiscovery overlaps CF AI enrichment with path-based discovery.
// Subdomains are probed first (~2s), enrichable results start CF AI immediately,
// and homepage + path probing runs concurrently with the ~20s CF AI call.
func (h *Handler) phasedComplianceDiscovery(ctx context.Context, phased compliance.PhasedDiscoverer, domain string, subdomains []string) ([]cloudflare.CompliancePage, error) {
	// Phase 1: quick subdomain probe (~2s)
	subdomainPages, err := phased.DiscoverSubdomains(ctx, domain, subdomains)
	if err != nil {
		return nil, err
	}

	enrichable, subPassthrough := splitByEnrichability(subdomainPages)
	log.Info().Str("domain", domain).Int("subdomain_pages", len(subdomainPages)).Int("enrichable", len(enrichable)).Msg("phased discovery: subdomains complete, starting CF AI")

	// Phase 2: start CF AI on subdomain enrichable pages while path discovery runs.
	// Path discovery may find more enrichable pages — those are fed into the same
	// worker pool via a shared channel so all CF AI calls run concurrently.
	allEnrichable := make(chan compliance.ClassifiedPage, maxCompliancePages)
	for _, p := range enrichable {
		allEnrichable <- p
	}

	// Path discovery feeds additional enrichable pages into the channel
	pathCh := lo.Async(func() []compliance.ClassifiedPage {
		pathPages, pathErr := phased.DiscoverPaths(ctx, domain, subdomainPages)
		if pathErr != nil {
			log.Warn().Err(pathErr).Str("domain", domain).Msg("path discovery failed, continuing with subdomain results")
			close(allEnrichable)
			return nil
		}

		allClassified := make([]compliance.ClassifiedPage, 0, len(subPassthrough)+len(pathPages))
		allClassified = append(allClassified, subPassthrough...)
		allClassified = append(allClassified, pathPages...)
		allClassified = compliance.PreferSubdomainPages(allClassified, domain)

		pathEnrichable, _ := splitByEnrichability(allClassified)
		for _, p := range pathEnrichable {
			allEnrichable <- p
		}

		close(allEnrichable)
		return allClassified
	})

	// Consume enrichable pages as they arrive (from subdomains first, then paths)
	cfPages := analyzeCompliancePages(ctx, h.enricher, allEnrichable)

	allClassified := <-pathCh
	log.Info().Str("domain", domain).Int("enriched_pages", len(cfPages)).Int("path_pages", len(allClassified)).Msg("phased discovery: CF AI and path probing complete")

	// Collect passthrough pages (non-enrichable)
	var passthrough []compliance.ClassifiedPage
	if allClassified != nil {
		_, passthrough = splitByEnrichability(allClassified)
	}
	passthrough = append(passthrough, subPassthrough...)

	passthroughPages := classifiedToCompliancePages(passthrough)

	pages := make([]cloudflare.CompliancePage, 0, len(cfPages)+len(passthroughPages))
	pages = append(pages, cfPages...)
	pages = append(pages, passthroughPages...)

	// Follow compliance_links from trust center pages (sub-nav pages with certs)
	followedPages := followComplianceLinks(ctx, h.enricher, cfPages)
	pages = append(pages, followedPages...)

	pages = deduplicateCompliancePages(pages)

	return pages, nil
}

// sequentialComplianceDiscovery is the original flow: full discovery, then enrichment.
// Used when the discoverer does not support phased discovery or no enricher is configured.
func (h *Handler) sequentialComplianceDiscovery(ctx context.Context, domain string) ([]cloudflare.CompliancePage, error) {
	classified, err := h.discoverer.Discover(ctx, domain)
	if err != nil {
		return nil, err
	}

	log.Info().Str("domain", domain).Int("classified_pages", len(classified)).Msg("compliance discovery complete")

	classified = deduplicateByPageType(classified)
	if len(classified) > maxCompliancePages {
		classified = classified[:maxCompliancePages]
	}

	var pages []cloudflare.CompliancePage

	if h.enricher != nil {
		enrichable, passthrough := splitByEnrichability(classified)
		cfPages := analyzeCompliancePagesSlice(ctx, h.enricher, enrichable)

		// Follow compliance_links from trust center pages
		followedPages := followComplianceLinks(ctx, h.enricher, cfPages)

		pages = append(pages, cfPages...)
		pages = append(pages, followedPages...)
		pages = append(pages, classifiedToCompliancePages(passthrough)...)
		log.Info().Str("domain", domain).Int("enriched_pages", len(enrichable)).Int("followed_pages", len(followedPages)).Int("passthrough_pages", len(passthrough)).Msg("cloudflare compliance analysis complete")
	} else {
		pages = classifiedToCompliancePages(classified)
	}

	return pages, nil
}

// deduplicateCompliancePages removes duplicate CompliancePage entries by URL.
func deduplicateCompliancePages(pages []cloudflare.CompliancePage) []cloudflare.CompliancePage {
	seen := make(map[string]struct{}, len(pages))
	result := make([]cloudflare.CompliancePage, 0, len(pages))

	for _, p := range pages {
		if _, exists := seen[p.URL]; exists {
			continue
		}

		seen[p.URL] = struct{}{}
		result = append(result, p)
	}

	return result
}

// classifiedToCompliancePages converts regex-classified pages to the CompliancePage format
// used when no Cloudflare enricher is configured
func classifiedToCompliancePages(classified []compliance.ClassifiedPage) []cloudflare.CompliancePage {
	pages := make([]cloudflare.CompliancePage, 0, len(classified))

	for _, cp := range classified {
		pages = append(pages, cloudflare.CompliancePage{
			URL:        cp.URL,
			PageType:   cp.PageType,
			Title:      cp.Title,
			Frameworks: cp.Frameworks,
		})
	}

	return pages
}

// buildComplianceSummary aggregates page types, frameworks, download links, and
// subprocessors from all analyzed pages into a summary.
func buildComplianceSummary(pages []cloudflare.CompliancePage) ComplianceSummary {
	summary := ComplianceSummary{PageCount: len(pages)}
	frameworkSet := make(map[string]struct{})
	downloadSet := make(map[string]struct{})
	subprocessorSet := make(map[string]struct{})

	for _, page := range pages {
		switch page.PageType {
		case compliance.PageTypePrivacyPolicy:
			summary.HasPrivacyPolicy = true
		case compliance.PageTypeTermsOfService:
			summary.HasTermsOfService = true
		case compliance.PageTypeTrustCenter:
			summary.HasTrustCenter = true
		case compliance.PageTypeDPA:
			summary.HasDPA = true
		case compliance.PageTypeSOC2Report:
			summary.HasSOC2 = true
		case compliance.PageTypeSecurity:
			summary.HasSecurityPage = true
		case compliance.PageTypeSubprocessors:
			summary.HasSubprocessors = true
		case compliance.PageTypeCookiePolicy:
			summary.HasCookiePolicy = true
		case compliance.PageTypeGDPR:
			summary.HasGDPR = true
		}

		for _, f := range page.Frameworks {
			frameworkSet[f] = struct{}{}
		}

		for _, dl := range page.DownloadLinks {
			if _, seen := downloadSet[dl]; !seen {
				downloadSet[dl] = struct{}{}
				summary.DownloadLinks = append(summary.DownloadLinks, dl)
			}
		}

		for _, sp := range page.Subprocessors {
			if _, seen := subprocessorSet[sp]; !seen {
				subprocessorSet[sp] = struct{}{}
				summary.Subprocessors = append(summary.Subprocessors, sp)
			}
		}
	}

	for f := range frameworkSet {
		summary.Frameworks = append(summary.Frameworks, f)
	}

	sort.Strings(summary.Frameworks)
	sort.Strings(summary.Subprocessors)

	// Promote HasSubprocessors if any subprocessors were extracted
	if len(summary.Subprocessors) > 0 {
		summary.HasSubprocessors = true
	}

	deriveFrameworkFlags(&summary)

	return summary
}

// deriveFrameworkFlags sets framework-specific boolean flags based on the frameworks list.
// Framework detection also promotes the corresponding coverage flag so that the
// coverage grid lights up regardless of whether a dedicated page was found.
func deriveFrameworkFlags(summary *ComplianceSummary) {
	for _, f := range summary.Frameworks {
		lower := strings.ToLower(f)

		switch {
		case strings.Contains(lower, "iso") && strings.Contains(lower, "27001"):
			summary.HasISO27001 = true
		case strings.Contains(lower, "hipaa"):
			summary.HasHIPAA = true
		case strings.Contains(lower, "pci") && strings.Contains(lower, "dss"):
			summary.HasPCIDSS = true
		case strings.Contains(lower, "soc") && strings.Contains(lower, "2"):
			summary.HasSOC2Framework = true
			summary.HasSOC2 = true
		case strings.Contains(lower, "gdpr"):
			summary.HasGDPRFramework = true
			summary.HasGDPR = true
		case strings.Contains(lower, "ccpa"):
			summary.HasCCPA = true
		case strings.Contains(lower, "fedramp"):
			summary.HasFedRAMP = true
		}
	}
}

// buildComplianceSlackMessage formats a compliance summary into a Slack Block Kit message
func buildComplianceSlackMessage(domain, email string, summary ComplianceSummary, pages []cloudflare.CompliancePage) slack.Message {
	headerText := fmt.Sprintf("Compliance Discovery: %s", domain)

	blocks := []slack.Block{
		{
			Type: "header",
			Text: &slack.TextObject{Type: "plain_text", Text: headerText},
		},
	}

	// Coverage summary
	var coverageItems []string
	if summary.HasPrivacyPolicy {
		coverageItems = append(coverageItems, "Privacy Policy")
	}

	if summary.HasTermsOfService {
		coverageItems = append(coverageItems, "Terms of Service")
	}

	if summary.HasTrustCenter {
		coverageItems = append(coverageItems, "Trust Center")
	}

	if summary.HasDPA {
		coverageItems = append(coverageItems, "DPA")
	}

	if summary.HasSOC2 {
		coverageItems = append(coverageItems, "SOC 2")
	}

	if summary.HasSecurityPage {
		coverageItems = append(coverageItems, "Security")
	}

	if summary.HasSubprocessors {
		coverageItems = append(coverageItems, "Subprocessors")
	}

	if summary.HasCookiePolicy {
		coverageItems = append(coverageItems, "Cookie Policy")
	}

	if summary.HasGDPR {
		coverageItems = append(coverageItems, "GDPR")
	}

	coverageText := "None found"
	if len(coverageItems) > 0 {
		coverageText = strings.Join(coverageItems, ", ")
	}

	var fields []slack.TextObject

	fields = append(fields, slack.TextObject{
		Type: "mrkdwn",
		Text: fmt.Sprintf("*Coverage:*\n%s", coverageText),
	})

	if email != "" {
		fields = append(fields, slack.TextObject{
			Type: "mrkdwn",
			Text: fmt.Sprintf("*Signup Email:*\n%s", email),
		})
	}

	fields = append(fields, slack.TextObject{
		Type: "mrkdwn",
		Text: fmt.Sprintf("*Pages Analyzed:*\n%d", len(pages)),
	})

	if len(summary.Frameworks) > 0 {
		fields = append(fields, slack.TextObject{
			Type: "mrkdwn",
			Text: fmt.Sprintf("*Frameworks:*\n%s", truncateText(strings.Join(summary.Frameworks, ", "), slackMessageTruncateLimit)),
		})
	}

	if len(summary.DownloadLinks) > 0 {
		fields = append(fields, slack.TextObject{
			Type: "mrkdwn",
			Text: fmt.Sprintf("*Downloadable Documents:*\n%d found", len(summary.DownloadLinks)),
		})
	}

	blocks = append(blocks, slack.Block{
		Type:   "section",
		Fields: fields,
	})

	// Add page details (up to 10 to avoid Slack block limits)
	pageLimit := len(pages)

	const maxSlackPageBlocks = 10

	if pageLimit > maxSlackPageBlocks {
		pageLimit = maxSlackPageBlocks
	}

	for i := 0; i < pageLimit; i++ {
		page := pages[i]
		pageText := fmt.Sprintf("*<%s|%s>*\n_%s_", page.URL, page.Title, page.Summary)
		blocks = append(blocks, slack.Block{
			Type: "section",
			Text: &slack.TextObject{
				Type: "mrkdwn",
				Text: truncateText(pageText, slackMessageTruncateLimit),
			},
		})
	}

	fallback := fmt.Sprintf("Compliance Discovery: %s — %d pages found", domain, len(pages))

	return slack.Message{
		Text:   fallback,
		Blocks: blocks,
	}
}

// enrichablePageTypes lists page types that benefit from Cloudflare AI browser
// rendering. Trust centers and security pages are often JavaScript SPAs that
// need rendering to extract subprocessors, frameworks, and compliance links.
// Other page types (privacy policy, terms, etc.) are adequately classified by
// the regex pipeline.
var enrichablePageTypes = map[string]struct{}{
	compliance.PageTypeTrustCenter:   {},
	compliance.PageTypeSecurity:      {},
	compliance.PageTypeSubprocessors: {},
}

// splitByEnrichability partitions classified pages into those that should be
// sent to Cloudflare AI for browser rendering and those that can be converted
// directly from regex classification.
func splitByEnrichability(pages []compliance.ClassifiedPage) (enrichable, passthrough []compliance.ClassifiedPage) {
	for _, p := range pages {
		if _, ok := enrichablePageTypes[p.PageType]; ok {
			enrichable = append(enrichable, p)
		} else {
			passthrough = append(passthrough, p)
		}
	}

	return enrichable, passthrough
}

// deduplicateByPageType keeps only the first occurrence of each page type,
// ensuring each type gets exactly one representative for analysis. This
// prevents the page cap from silently dropping entire page types when a
// domain has many pages of the same type (e.g., multiple terms_of_service URLs).
func deduplicateByPageType(pages []compliance.ClassifiedPage) []compliance.ClassifiedPage {
	seen := make(map[string]struct{}, len(pages))
	result := make([]compliance.ClassifiedPage, 0, len(pages))

	for _, p := range pages {
		if _, exists := seen[p.PageType]; exists {
			continue
		}

		seen[p.PageType] = struct{}{}
		result = append(result, p)
	}

	return result
}

func respondComplianceError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, ComplianceResponse{
		Success: false,
		Error: &Error{
			Code:    code,
			Message: message,
		},
	})
}
