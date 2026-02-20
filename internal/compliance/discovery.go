package compliance

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/rs/zerolog/log"
	"github.com/samber/lo"
)

const (
	// defaultProbeTimeout is the per-request timeout for httpx probing.
	// Most compliance pages respond within 2s; 5s allows for slower hosts
	// without blocking the pipeline on dead targets.
	defaultProbeTimeout = 5 * time.Second
	// defaultMaxTargets caps the number of URLs to probe in batch
	defaultMaxTargets = 50
	// defaultProbeThreads controls concurrent probe workers
	defaultProbeThreads = 10
	// defaultMaxRedirects is the maximum redirect hops during probing
	defaultMaxRedirects = 5
	// defaultMaxResponseBodySize is the maximum response body bytes to read (256KB)
	defaultMaxResponseBodySize = 256 * 1024
	// bodyClassifyLimit limits body content scanned for regex classification (32KB)
	bodyClassifyLimit = 32 * 1024
	// dnsResolveTimeout is the per-lookup timeout for subdomain DNS resolution
	dnsResolveTimeout = 2 * time.Second
	// httpSuccessStatus is the HTTP status code indicating a successful response
	httpSuccessStatus = 200
	// minRegexMatchGroups is the minimum submatch length for a regex with one capture group
	minRegexMatchGroups = 2
)

// linkPattern matches href attributes in anchor tags for link extraction
var linkPattern = regexp.MustCompile(`(?i)<a\s[^>]*href=["']([^"'#][^"']*)["']`)

// complianceLinkFilter matches links likely to be compliance-related by href or anchor text
var complianceLinkFilter = regexp.MustCompile(
	`(?i)(privac|terms|legal|trust|security|compliance|dpa|data.?process|` +
		`cookie|gdpr|subprocessor|soc.?2|hipaa|iso.?27001|ccpa|policy|tos(/|$))`,
)

// titlePattern extracts the page title from HTML
var titlePattern = regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)

// deepCrawlablePageTypes lists page classifications that trigger deep crawling of internal links
var deepCrawlablePageTypes = map[string]struct{}{
	PageTypeTrustCenter: {},
	PageTypeSecurity:    {},
}

// supplementarySubdomains are well-known compliance subdomains to probe alongside path-based targets
var supplementarySubdomains = []string{
	"trust",
	"security",
	"compliance",
	"legal",
	"privacy",
	"terms",
	"status",
}

// supplementaryPaths are well-known compliance paths to probe alongside links discovered from the homepage
var supplementaryPaths = []string{
	"/privacy",
	"/privacy-policy",
	"/legal/privacy",
	"/legal/privacy-policy",
	"/terms",
	"/terms-of-service",
	"/tos",
	"/legal/terms",
	"/security",
	"/security.txt",
	"/.well-known/security.txt",
	"/trust",
	"/trust-center",
	"/trustcenter",
	"/compliance",
	"/dpa",
	"/legal/dpa",
	"/data-processing-agreement",
	"/legal",
	"/subprocessors",
	"/legal/subprocessors",
	"/legal/sub-processors",
	"/cookie-policy",
	"/cookies",
	"/gdpr",
}

// Discoverer discovers compliance-related pages for a domain
type Discoverer interface {
	// Discover performs compliance page discovery and classification for the given domain
	Discover(ctx context.Context, domain string) ([]ClassifiedPage, error)
}

// PhasedDiscoverer extends Discoverer with phased discovery methods that allow
// the caller to overlap downstream processing (e.g., AI enrichment) with
// ongoing discovery. Subdomain results arrive first because trust centers and
// security pages are typically hosted on dedicated subdomains.
type PhasedDiscoverer interface {
	Discoverer
	// DiscoverSubdomains probes compliance-relevant subdomains. When knownSubdomains
	// is non-empty, filters those for compliance patterns. Otherwise resolves a
	// static list of well-known compliance subdomain prefixes via DNS.
	DiscoverSubdomains(ctx context.Context, domain string, knownSubdomains []string) ([]ClassifiedPage, error)
	// DiscoverPaths probes homepage links and supplementary paths, then deep crawls.
	// The existing parameter contains pages already found by DiscoverSubdomains so
	// they can be excluded from probing and included in deep crawl scope.
	DiscoverPaths(ctx context.Context, domain string, existing []ClassifiedPage) ([]ClassifiedPage, error)
}

// Options configures compliance discovery behavior
type Options struct {
	probeTimeout        time.Duration
	maxTargets          int
	probeThreads        int
	maxRedirects        int
	maxResponseBodySize int64
}

// Option is a functional option for configuring compliance discovery
type Option func(*Options)

// WithProbeTimeout sets the per-request probe timeout
func WithProbeTimeout(d time.Duration) Option {
	return func(o *Options) {
		if d > 0 {
			o.probeTimeout = d
		}
	}
}

// WithMaxTargets sets the maximum number of URLs to probe
func WithMaxTargets(n int) Option {
	return func(o *Options) {
		if n > 0 {
			o.maxTargets = n
		}
	}
}

// WithProbeThreads sets the concurrent probe worker count
func WithProbeThreads(n int) Option {
	return func(o *Options) {
		if n > 0 {
			o.probeThreads = n
		}
	}
}

// HTTPXDiscoverer implements Discoverer using projectdiscovery/httpx
type HTTPXDiscoverer struct {
	options *Options
}

// NewHTTPXDiscoverer creates a compliance discoverer with the given options
func NewHTTPXDiscoverer(opts ...Option) *HTTPXDiscoverer {
	o := &Options{
		probeTimeout:        defaultProbeTimeout,
		maxTargets:          defaultMaxTargets,
		probeThreads:        defaultProbeThreads,
		maxRedirects:        defaultMaxRedirects,
		maxResponseBodySize: defaultMaxResponseBodySize,
	}

	for _, opt := range opts {
		opt(o)
	}

	return &HTTPXDiscoverer{options: o}
}

// Discover performs compliance discovery by probing subdomains and homepage
// links concurrently, then deep crawling trust center pages for sub-links.
// This is the combined flow; use DiscoverSubdomains + DiscoverPaths for
// phased discovery that allows overlapping downstream processing.
func (d *HTTPXDiscoverer) Discover(ctx context.Context, domain string) ([]ClassifiedPage, error) {
	if domain == "" {
		return nil, ErrInvalidDomain
	}

	client, err := d.newHTTPXClient()
	if err != nil {
		return nil, fmt.Errorf("initializing httpx client: %w", err)
	}

	// Probe subdomains and extract homepage links concurrently.
	// Subdomains finish in ~2s while homepage fetch takes ~5s.
	subTargets := buildSubdomainTargets(ctx, domain)
	subCh := lo.Async(func() []ClassifiedPage {
		return d.probeAndClassify(ctx, client, subTargets)
	})

	homepageLinks := d.extractHomepageLinks(ctx, client, domain)

	subdomainPages := <-subCh
	log.Info().Str("domain", domain).Int("homepage_links", len(homepageLinks)).Int("subdomain_pages", len(subdomainPages)).Msg("parallel discovery phase complete")

	// Build path targets, excluding URLs already found via subdomains
	existingURLs := make(map[string]struct{}, len(subdomainPages))
	for _, p := range subdomainPages {
		existingURLs[p.URL] = struct{}{}
	}

	pathTargets := buildPathTargets(homepageLinks, domain, existingURLs)
	if len(pathTargets) > d.options.maxTargets {
		pathTargets = pathTargets[:d.options.maxTargets]
	}

	log.Info().Str("domain", domain).Int("probe_targets", len(pathTargets)).Msg("path probe target list built")

	pathPages := d.probeAndClassify(ctx, client, pathTargets)

	pages := make([]ClassifiedPage, 0, len(subdomainPages)+len(pathPages))
	pages = append(pages, subdomainPages...)
	pages = append(pages, pathPages...)
	log.Info().Str("domain", domain).Int("classified_pages", len(pages)).Msg("compliance page classification complete")

	deepPages := d.deepCrawlCompliancePages(ctx, client, pages, domain)
	pages = append(pages, deepPages...)
	log.Info().Str("domain", domain).Int("deep_crawl_pages", len(deepPages)).Msg("deep crawl complete")

	pages = PreferSubdomainPages(pages, domain)
	log.Info().Str("domain", domain).Int("final_pages", len(pages)).Msg("subdomain prioritization complete")

	return pages, nil
}

// DiscoverSubdomains probes compliance-relevant subdomains. When knownSubdomains
// contains pre-discovered subdomains (e.g., from subfinder), it filters those for
// compliance-relevant patterns. Otherwise it resolves the static supplementary
// subdomain list via DNS to discover live compliance subdomains.
func (d *HTTPXDiscoverer) DiscoverSubdomains(ctx context.Context, domain string, knownSubdomains []string) ([]ClassifiedPage, error) {
	if domain == "" {
		return nil, ErrInvalidDomain
	}

	client, err := d.newHTTPXClient()
	if err != nil {
		return nil, fmt.Errorf("initializing httpx client: %w", err)
	}

	var targets []string

	if len(knownSubdomains) > 0 {
		targets = filterComplianceSubdomains(knownSubdomains)
		log.Info().Str("domain", domain).Int("known", len(knownSubdomains)).Int("compliance_relevant", len(targets)).Msg("filtered known subdomains for compliance")
	} else {
		targets = buildSubdomainTargets(ctx, domain)
	}

	pages := d.probeAndClassify(ctx, client, targets)
	log.Info().Str("domain", domain).Int("subdomain_pages", len(pages)).Msg("subdomain discovery complete")

	return pages, nil
}

// DiscoverPaths probes homepage links and supplementary paths, deep crawls
// trust center pages, and returns only the pages not already in existing.
func (d *HTTPXDiscoverer) DiscoverPaths(ctx context.Context, domain string, existing []ClassifiedPage) ([]ClassifiedPage, error) {
	if domain == "" {
		return nil, ErrInvalidDomain
	}

	client, err := d.newHTTPXClient()
	if err != nil {
		return nil, fmt.Errorf("initializing httpx client: %w", err)
	}

	homepageLinks := d.extractHomepageLinks(ctx, client, domain)
	log.Info().Str("domain", domain).Int("homepage_links", len(homepageLinks)).Msg("homepage link extraction complete")

	existingURLs := make(map[string]struct{}, len(existing))
	for _, p := range existing {
		existingURLs[p.URL] = struct{}{}
	}

	targets := buildPathTargets(homepageLinks, domain, existingURLs)
	if len(targets) > d.options.maxTargets {
		targets = targets[:d.options.maxTargets]
	}

	log.Info().Str("domain", domain).Int("probe_targets", len(targets)).Msg("path probe target list built")

	pathPages := d.probeAndClassify(ctx, client, targets)
	log.Info().Str("domain", domain).Int("classified_pages", len(pathPages)).Msg("path classification complete")

	// Deep crawl needs all known pages to identify crawlable trust centers
	allPages := make([]ClassifiedPage, 0, len(existing)+len(pathPages))
	allPages = append(allPages, existing...)
	allPages = append(allPages, pathPages...)

	deepPages := d.deepCrawlCompliancePages(ctx, client, allPages, domain)
	pathPages = append(pathPages, deepPages...)
	log.Info().Str("domain", domain).Int("deep_crawl_pages", len(deepPages)).Msg("deep crawl complete")

	return pathPages, nil
}

// newHTTPXClient creates a configured httpx client
func (d *HTTPXDiscoverer) newHTTPXClient() (*httpx.HTTPX, error) {
	return httpx.New(&httpx.Options{
		Timeout:                   d.options.probeTimeout,
		FollowRedirects:           true,
		MaxRedirects:              d.options.maxRedirects,
		MaxResponseBodySizeToRead: d.options.maxResponseBodySize,
		DefaultUserAgent:          "Mozilla/5.0 (compatible; Sleuth/1.0)",
	})
}

// extractHomepageLinks fetches the homepage and returns compliance-related links found in the body
func (d *HTTPXDiscoverer) extractHomepageLinks(ctx context.Context, client *httpx.HTTPX, domain string) []string {
	homepageURL := fmt.Sprintf("https://%s", domain)

	req, err := client.NewRequestWithContext(ctx, "GET", homepageURL)
	if err != nil {
		log.Warn().Err(err).Str("domain", domain).Msg("failed to create homepage request")
		return nil
	}

	resp, err := client.Do(req, httpx.UnsafeOptions{})
	if err != nil {
		log.Warn().Err(err).Str("domain", domain).Msg("homepage fetch failed")
		return nil
	}

	if resp.StatusCode != httpSuccessStatus {
		log.Warn().Str("domain", domain).Int("status", resp.StatusCode).Msg("homepage returned non-200 status")
		return nil
	}

	return extractLinksFromHTML(string(resp.Data), domain)
}

// probeAndClassify sends concurrent GET requests to all targets and classifies responses
func (d *HTTPXDiscoverer) probeAndClassify(ctx context.Context, client *httpx.HTTPX, targets []string) []ClassifiedPage {
	var (
		mu    sync.Mutex
		seen  = make(map[string]struct{})
		pages []ClassifiedPage
		wg    sync.WaitGroup
	)

	sem := make(chan struct{}, d.options.probeThreads)

	for _, target := range targets {
		wg.Add(1)

		go func(targetURL string) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			req, err := client.NewRequestWithContext(ctx, "GET", targetURL)
			if err != nil {
				return
			}

			resp, err := client.Do(req, httpx.UnsafeOptions{})
			if err != nil {
				return
			}

			if resp.StatusCode != httpSuccessStatus {
				return
			}

			body := string(resp.Data)

			// Extract title from HTML
			title := extractTitle(body)

			// Limit body size for classification to avoid regex over large pages
			classifyBody := body
			if len(classifyBody) > bodyClassifyLimit {
				classifyBody = classifyBody[:bodyClassifyLimit]
			}

			pageType := ClassifyPage(targetURL, title, classifyBody)
			if pageType == "" {
				return
			}

			// Determine final URL from redirect chain
			finalURL := targetURL
			if resp.HasChain() {
				if last := resp.GetChainLastURL(); last != "" {
					finalURL = last
				}
			}

			mu.Lock()
			if _, dup := seen[finalURL]; !dup {
				seen[finalURL] = struct{}{}
				pages = append(pages, ClassifiedPage{
					URL:        finalURL,
					Title:      title,
					PageType:   pageType,
					StatusCode: resp.StatusCode,
				})
			}
			mu.Unlock()
		}(target)
	}

	wg.Wait()

	return pages
}

// extractLinksFromHTML parses anchor tags from HTML body and returns
// compliance-related hrefs resolved against the base domain
func extractLinksFromHTML(body, domain string) []string {
	matches := linkPattern.FindAllStringSubmatch(body, -1)
	seen := make(map[string]struct{})

	var links []string

	for _, match := range matches {
		if len(match) < minRegexMatchGroups {
			continue
		}

		href := strings.TrimSpace(match[1])
		if href == "" {
			continue
		}

		// Filter to compliance-related links only
		if !complianceLinkFilter.MatchString(href) {
			continue
		}

		normalized := NormalizeURL(href, domain)

		if _, ok := seen[normalized]; ok {
			continue
		}

		// Skip external domains
		if !isSameDomain(normalized, domain) {
			continue
		}

		seen[normalized] = struct{}{}
		links = append(links, normalized)
	}

	return links
}

// extractAllInternalLinks extracts all same-domain links from HTML without compliance filtering.
// This is used for deep crawling trust center pages where all internal links are contextually relevant.
func extractAllInternalLinks(body, baseDomain string) []string {
	matches := linkPattern.FindAllStringSubmatch(body, -1)
	seen := make(map[string]struct{})

	var links []string

	for _, match := range matches {
		if len(match) < minRegexMatchGroups {
			continue
		}

		href := strings.TrimSpace(match[1])
		if href == "" {
			continue
		}

		normalized := NormalizeURL(href, baseDomain)

		if _, ok := seen[normalized]; ok {
			continue
		}

		if !isSameDomain(normalized, baseDomain) {
			continue
		}

		seen[normalized] = struct{}{}
		links = append(links, normalized)
	}

	return links
}

// deepCrawlCompliancePages re-fetches pages classified as trust_center or security,
// extracts all internal links from them, probes and classifies those linked pages,
// and returns only pages not already present in the initial set. Also analyzes
// trust center content for embedded compliance indicators and external links.
func (d *HTTPXDiscoverer) deepCrawlCompliancePages(ctx context.Context, client *httpx.HTTPX, initialPages []ClassifiedPage, domain string) []ClassifiedPage {
	existingURLs := make(map[string]struct{}, len(initialPages))
	existingTypes := make(map[string]struct{}, len(initialPages))

	for _, p := range initialPages {
		existingURLs[p.URL] = struct{}{}
		existingTypes[p.PageType] = struct{}{}
	}

	var (
		candidateURLs []string
		inferredPages []ClassifiedPage
	)

	candidateSeen := make(map[string]struct{})

	for i := range initialPages {
		if _, ok := deepCrawlablePageTypes[initialPages[i].PageType]; !ok {
			continue
		}

		pageURL := initialPages[i].URL

		req, err := client.NewRequestWithContext(ctx, "GET", pageURL)
		if err != nil {
			log.Warn().Err(err).Str("url", pageURL).Msg("failed to create deep crawl request")
			continue
		}

		resp, err := client.Do(req, httpx.UnsafeOptions{})
		if err != nil {
			log.Warn().Err(err).Str("url", pageURL).Msg("deep crawl fetch failed")
			continue
		}

		if resp.StatusCode != httpSuccessStatus {
			continue
		}

		body := string(resp.Data)

		// Extract same-domain links for probing
		internalLinks := extractAllInternalLinks(body, domain)
		for _, link := range internalLinks {
			if _, already := existingURLs[link]; already {
				continue
			}

			if _, seen := candidateSeen[link]; seen {
				continue
			}

			candidateSeen[link] = struct{}{}
			candidateURLs = append(candidateURLs, link)
		}

		// Analyze trust center body for compliance indicators and external links
		analysis := AnalyzeTrustCenterContent(body, pageURL, domain)

		// Annotate frameworks on the original trust center page
		if len(analysis.Frameworks) > 0 {
			initialPages[i].Frameworks = analysis.Frameworks
			log.Info().Str("url", pageURL).Strs("frameworks", analysis.Frameworks).Msg("trust center content analysis found frameworks")
		}

		for _, inferred := range analysis.InferredPages {
			if _, hasType := existingTypes[inferred.PageType]; hasType {
				continue
			}

			existingTypes[inferred.PageType] = struct{}{}
			inferredPages = append(inferredPages, inferred)
		}

		// Add external compliance links as probe candidates
		for _, extLink := range analysis.ExternalLinks {
			if _, already := existingURLs[extLink]; already {
				continue
			}

			if _, seen := candidateSeen[extLink]; seen {
				continue
			}

			candidateSeen[extLink] = struct{}{}
			candidateURLs = append(candidateURLs, extLink)
		}
	}

	var result []ClassifiedPage
	result = append(result, inferredPages...)

	if len(candidateURLs) > 0 {
		log.Info().Int("candidate_links", len(candidateURLs)).Msg("deep crawl extracted candidate links")

		probed := d.probeAndClassify(ctx, client, candidateURLs)
		result = append(result, probed...)
	}

	return result
}

// extractTitle extracts the page title from HTML content
func extractTitle(body string) string {
	match := titlePattern.FindStringSubmatch(body)
	if len(match) < minRegexMatchGroups {
		return ""
	}

	return strings.TrimSpace(match[1])
}

// complianceSubdomainPattern matches subdomain prefixes that are compliance-relevant.
var complianceSubdomainPattern = regexp.MustCompile(
	`(?i)^(trust|security|compliance|legal|privacy|terms|status|dpa|gdpr|subprocessor)\.`,
)

// filterComplianceSubdomains takes a list of discovered subdomains (FQDNs)
// and returns HTTPS URLs for those matching compliance-relevant patterns.
func filterComplianceSubdomains(subdomains []string) []string {
	var targets []string

	for _, sub := range subdomains {
		if complianceSubdomainPattern.MatchString(sub) {
			targets = append(targets, fmt.Sprintf("https://%s", sub))
		}
	}

	return targets
}

// buildSubdomainTargets resolves well-known compliance subdomains via DNS
// and returns probe URLs only for those that actually exist. This avoids
// wasting time on HTTP timeouts for non-existent subdomains.
func buildSubdomainTargets(ctx context.Context, domain string) []string {
	fqdns := lo.Map(supplementarySubdomains, func(sub string, _ int) string {
		return fmt.Sprintf("%s.%s", sub, domain)
	})

	live := resolveSubdomains(ctx, fqdns)
	log.Info().Str("domain", domain).Int("checked", len(fqdns)).Int("resolved", len(live)).Msg("subdomain DNS resolution complete")

	return lo.Map(live, func(fqdn string, _ int) string {
		return fmt.Sprintf("https://%s", fqdn)
	})
}

// resolveSubdomains performs concurrent DNS lookups and returns only FQDNs
// that resolve to at least one address.
func resolveSubdomains(ctx context.Context, fqdns []string) []string {
	var (
		mu   sync.Mutex
		live []string
		wg   sync.WaitGroup
	)

	resolver := net.DefaultResolver

	for _, fqdn := range fqdns {
		wg.Add(1)

		go func(host string) {
			defer wg.Done()

			dnsCtx, cancel := context.WithTimeout(ctx, dnsResolveTimeout)
			defer cancel()

			addrs, err := resolver.LookupHost(dnsCtx, host)
			if err != nil || len(addrs) == 0 {
				return
			}

			mu.Lock()
			live = append(live, host)
			mu.Unlock()
		}(fqdn)
	}

	wg.Wait()

	return live
}

// buildPathTargets returns probe URLs from homepage links and supplementary
// paths, excluding any URLs already discovered (e.g., via subdomain probing).
func buildPathTargets(homepageLinks []string, domain string, exclude map[string]struct{}) []string {
	seen := make(map[string]struct{}, len(exclude))
	for k := range exclude {
		seen[k] = struct{}{}
	}

	var targets []string

	// Homepage-extracted links first (highest confidence)
	for _, link := range homepageLinks {
		normalized := NormalizeURL(link, domain)
		if _, ok := seen[normalized]; !ok {
			seen[normalized] = struct{}{}
			targets = append(targets, normalized)
		}
	}

	// Supplementary known paths (lower confidence — guessed paths)
	for _, path := range supplementaryPaths {
		normalized := NormalizeURL(path, domain)
		if _, ok := seen[normalized]; !ok {
			seen[normalized] = struct{}{}
			targets = append(targets, normalized)
		}
	}

	return targets
}

// PreferSubdomainPages deduplicates pages by page type, preferring subdomain
// URLs over root-domain path matches. When the same page type is found at both
// trust.example.com and example.com/trust, only the subdomain result is kept.
func PreferSubdomainPages(pages []ClassifiedPage, domain string) []ClassifiedPage {
	byType := make(map[string][]ClassifiedPage)
	for _, p := range pages {
		byType[p.PageType] = append(byType[p.PageType], p)
	}

	var result []ClassifiedPage

	for _, entries := range byType {
		if len(entries) == 1 {
			result = append(result, entries[0])
			continue
		}

		var subdomainEntries, rootEntries []ClassifiedPage

		for _, e := range entries {
			parsed, err := url.Parse(e.URL)
			if err != nil {
				rootEntries = append(rootEntries, e)
				continue
			}

			host := parsed.Hostname()
			if host != domain && strings.HasSuffix(host, "."+domain) {
				subdomainEntries = append(subdomainEntries, e)
			} else {
				rootEntries = append(rootEntries, e)
			}
		}

		if len(subdomainEntries) > 0 {
			result = append(result, subdomainEntries...)
		} else {
			result = append(result, rootEntries...)
		}
	}

	return result
}

// NormalizeURL resolves a potentially relative URL against the domain
func NormalizeURL(rawURL, domain string) string {
	rawURL = strings.TrimSpace(rawURL)

	if strings.HasPrefix(rawURL, "/") {
		return fmt.Sprintf("https://%s%s", domain, rawURL)
	}

	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme == "" {
		return fmt.Sprintf("https://%s/%s", domain, strings.TrimPrefix(rawURL, "/"))
	}

	return rawURL
}

// isSameDomain checks whether a URL belongs to the given domain
func isSameDomain(rawURL, domain string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	host := parsed.Hostname()

	return host == domain || strings.HasSuffix(host, "."+domain)
}
