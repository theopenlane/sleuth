package scanner

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/projectdiscovery/goflags"
	subfinderrunner "github.com/projectdiscovery/subfinder/v2/pkg/runner"
	"github.com/rs/zerolog/log"

	"github.com/theopenlane/sleuth/internal/types"
)

// performSubdomainDiscovery performs subdomain discovery and precision takeover checks.
func (s *Scanner) performSubdomainDiscovery(ctx context.Context, domain string) *types.CheckResult {
	result := newCheckResult("subdomain_discovery")

	buf := &bytes.Buffer{}
	opts := &subfinderrunner.Options{
		Domain:  goflags.StringSlice{domain},
		Sources: goflags.StringSlice(s.options.SubfinderSources),
		Threads: s.options.SubfinderThreads,
		Output:  buf,
		Silent:  s.options.Silent && !s.options.Verbose,
	}

	runner, err := subfinderrunner.NewRunner(opts)
	if err != nil {
		markCheckError(result, "subfinder init failed: %v", err)
		return result
	}

	if err := runner.RunEnumerationWithCtx(ctx); err != nil {
		markCheckError(result, "subfinder run failed: %v", err)
		return result
	}

	discoveredSubdomains := parseDiscoveredSubdomains(buf.String())

	// Active probing of common prefixes that passive sources may miss
	alreadyFound := make(map[string]struct{}, len(discoveredSubdomains))
	for _, sub := range discoveredSubdomains {
		alreadyFound[sub] = struct{}{}
	}

	activelyFound := s.probeCommonSubdomains(ctx, domain, alreadyFound)
	discoveredSubdomains = append(discoveredSubdomains, activelyFound...)
	sort.Strings(discoveredSubdomains)
	log.Info().Str("domain", domain).Int("passive", len(alreadyFound)).Int("active", len(activelyFound)).Msg("subdomain probing complete")

	if limit := s.options.MaxSubdomains; limit > 0 && len(discoveredSubdomains) > limit {
		discoveredSubdomains = discoveredSubdomains[:limit]
	}

	interesting := make([]string, 0)
	for _, subdomain := range discoveredSubdomains {
		subOnly := strings.TrimSuffix(subdomain, "."+domain)
		if contextText, ok := s.interestingSubdomainContext(subOnly); ok {
			interesting = append(interesting, subdomain)
			result.Findings = append(result.Findings, types.Finding{
				Severity:    "info",
				Type:        "interesting_subdomain",
				Description: fmt.Sprintf("Interesting subdomain discovered: %s", subdomain),
				Details:     contextText,
			})
		}
	}

	// Build context map for HTTP probing
	interestingContextMap := make(map[string]string, len(interesting))
	for _, sub := range interesting {
		subOnly := strings.TrimSuffix(sub, "."+domain)
		if ctxText, ok := s.interestingSubdomainContext(subOnly); ok {
			interestingContextMap[sub] = ctxText
		}
	}

	// HTTP-probe interesting subdomains for liveness and page titles
	var interestingDetails []InterestingSubdomainInfo
	if len(interesting) > 0 {
		interestingDetails = s.probeInterestingSubdomains(ctx, interesting, interestingContextMap)
		log.Info().Str("domain", domain).Int("probed", len(interesting)).Int("live", countLiveSubdomains(interestingDetails)).Msg("interesting subdomain probing complete")
	}

	result.Metadata["total_subdomains"] = len(discoveredSubdomains)
	result.Metadata["subdomains"] = discoveredSubdomains
	result.Metadata["interesting_subdomains"] = interesting

	if len(interestingDetails) > 0 {
		result.Metadata["interesting_subdomain_details"] = interestingDetails

		// Update existing interesting_subdomain findings with HTTP status
		for i := range result.Findings {
			if result.Findings[i].Type != "interesting_subdomain" {
				continue
			}

			for _, detail := range interestingDetails {
				if !strings.Contains(result.Findings[i].Description, detail.Subdomain) {
					continue
				}

				if detail.Live {
					result.Findings[i].Details = fmt.Sprintf("%s (HTTP %d — %s)", result.Findings[i].Details, detail.StatusCode, detail.URL)
				} else {
					result.Findings[i].Details = fmt.Sprintf("%s (not responding to HTTP)", result.Findings[i].Details)
				}

				break
			}
		}
	}

	if len(discoveredSubdomains) > 0 {
		result.Findings = append(result.Findings, types.Finding{
			Severity:    "info",
			Type:        "subdomain_count",
			Description: fmt.Sprintf("Discovered %d subdomains", len(discoveredSubdomains)),
			Details:     fmt.Sprintf("Found %d interesting subdomains out of %d total", len(interesting), len(discoveredSubdomains)),
		})
	}

	s.checkSubdomainTakeovers(ctx, discoveredSubdomains, result)

	return result
}

func parseDiscoveredSubdomains(raw string) []string {
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	seen := make(map[string]struct{}, len(lines))

	results := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if _, exists := seen[line]; exists {
			continue
		}

		seen[line] = struct{}{}
		results = append(results, line)
	}

	sort.Strings(results)

	return results
}

func (s *Scanner) interestingSubdomainContext(subdomain string) (string, bool) {
	lower := strings.ToLower(subdomain)

	for _, pattern := range s.options.InterestingSubdomainPatterns {
		if !strings.Contains(lower, pattern) {
			continue
		}

		contextText := s.options.InterestingSubdomainContexts[pattern]
		if contextText == "" {
			contextText = "Potentially sensitive service"
		}

		return contextText, true
	}

	return "", false
}

// probeCommonSubdomains actively resolves common subdomain prefixes via DNS
// to discover subdomains that passive OSINT sources may have missed.
func (s *Scanner) probeCommonSubdomains(ctx context.Context, domain string, alreadyFound map[string]struct{}) []string {
	var (
		mu    sync.Mutex
		found []string
		wg    sync.WaitGroup
	)

	workers := s.options.HTTPThreads
	if workers <= 0 {
		workers = 1
	}

	sem := make(chan struct{}, workers)
	resolver := net.DefaultResolver

	for _, prefix := range s.options.InterestingSubdomainPatterns {
		fqdn := fmt.Sprintf("%s.%s", prefix, domain)
		if _, exists := alreadyFound[fqdn]; exists {
			continue
		}

		wg.Add(1)

		go func(subdomain string) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			dnsCtx, cancel := s.withDNSTimeout(ctx)
			defer cancel()

			addrs, err := resolver.LookupHost(dnsCtx, subdomain)
			if err != nil || len(addrs) == 0 {
				return
			}

			mu.Lock()
			found = append(found, subdomain)
			mu.Unlock()
		}(fqdn)
	}

	wg.Wait()

	sort.Strings(found)

	return found
}

// InterestingSubdomainInfo holds HTTP probe results for an interesting subdomain.
type InterestingSubdomainInfo struct {
	// Subdomain is the fully qualified subdomain name.
	Subdomain string `json:"subdomain"`
	// Context describes why this subdomain is interesting.
	Context string `json:"context"`
	// Live indicates whether the subdomain responded to an HTTP request.
	Live bool `json:"live"`
	// StatusCode is the HTTP status code returned, if live.
	StatusCode int `json:"status_code,omitempty"`
	// Title is the page title extracted from the HTML response, if live.
	Title string `json:"title,omitempty"`
	// URL is the final URL after following redirects, if live.
	URL string `json:"url,omitempty"`
}

// maxTitleReadBytes caps how many bytes we read from the response body when extracting a title.
const maxTitleReadBytes = 64 * 1024

// titlePattern matches the HTML <title> tag content.
var titlePattern = regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)

// probeInterestingSubdomains performs HTTP GET probes against interesting subdomains
// to determine liveness, extract page titles, and capture final URLs.
// The contextMap provides pre-resolved context descriptions keyed by subdomain FQDN.
func (s *Scanner) probeInterestingSubdomains(ctx context.Context, subdomains []string, contextMap map[string]string) []InterestingSubdomainInfo {
	var (
		mu      sync.Mutex
		results []InterestingSubdomainInfo
		wg      sync.WaitGroup
	)

	workers := s.options.HTTPThreads
	if workers <= 0 {
		workers = 1
	}

	sem := make(chan struct{}, workers)

	timeout := s.options.HTTPTimeout
	if timeout <= 0 {
		timeout = defaultHTTPTimeout
	}

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // probing unknown subdomains
		},
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			const maxRedirects = 10
			if len(via) >= maxRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	for _, subdomain := range subdomains {
		contextText := contextMap[subdomain]

		wg.Add(1)

		go func(sub, ctxText string) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			info := InterestingSubdomainInfo{
				Subdomain: sub,
				Context:   ctxText,
			}

			// Try HTTPS first, fall back to HTTP
			for _, scheme := range []string{"https", "http"} {
				probeURL := fmt.Sprintf("%s://%s", scheme, sub)

				req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
				if err != nil {
					continue
				}

				resp, err := client.Do(req)
				if err != nil {
					continue
				}

				info.Live = true
				info.StatusCode = resp.StatusCode
				info.URL = resp.Request.URL.String()

				body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxTitleReadBytes))
				resp.Body.Close()

				if readErr == nil {
					if match := titlePattern.FindSubmatch(body); len(match) > 1 {
						info.Title = strings.TrimSpace(string(match[1]))
					}
				}

				break
			}

			mu.Lock()
			results = append(results, info)
			mu.Unlock()
		}(subdomain, contextText)
	}

	wg.Wait()

	sort.Slice(results, func(i, j int) bool {
		return results[i].Subdomain < results[j].Subdomain
	})

	return results
}

// countLiveSubdomains returns the number of probed subdomains that responded to HTTP.
func countLiveSubdomains(details []InterestingSubdomainInfo) int {
	count := 0
	for _, d := range details {
		if d.Live {
			count++
		}
	}

	return count
}

func (s *Scanner) takeoverWorkerCount(checkLimit int) int {
	if checkLimit <= 0 {
		return 1
	}

	workerCount := checkLimit
	if s.options.MaxConcurrency > 0 && workerCount > s.options.MaxConcurrency {
		workerCount = s.options.MaxConcurrency
	}
	if s.options.HTTPThreads > 0 && workerCount > s.options.HTTPThreads {
		workerCount = s.options.HTTPThreads
	}
	if workerCount <= 0 {
		return 1
	}

	return workerCount
}

// checkSubdomainTakeovers checks for confirmed subdomain takeover vulnerabilities.
func (s *Scanner) checkSubdomainTakeovers(ctx context.Context, subdomains []string, result *types.CheckResult) {
	if len(subdomains) == 0 {
		return
	}

	checkLimit := len(subdomains)
	if maxChecks := s.options.MaxSubdomainTakeoverChecks; maxChecks > 0 && checkLimit > maxChecks {
		checkLimit = maxChecks
	}
	if checkLimit <= 0 {
		return
	}

	resolver := net.DefaultResolver
	subset := subdomains[:checkLimit]
	workers := s.takeoverWorkerCount(checkLimit)

	jobs := make(chan string, checkLimit)
	out := make(chan types.Finding, checkLimit)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for subdomain := range jobs {
				dnsCtx, cancel := s.withDNSTimeout(ctx)
				cname, err := resolver.LookupCNAME(dnsCtx, subdomain)
				cancel()
				if err != nil || cname == subdomain+"." {
					continue
				}

				cnameClean := strings.TrimSuffix(cname, ".")
				fingerprint, ok := s.takeoverFingerprintForCNAME(cnameClean)
				if !ok {
					continue
				}

				confirmed, evidence := s.confirmSubdomainTakeover(ctx, subdomain, cnameClean, fingerprint)
				if !confirmed {
					continue
				}

				out <- types.Finding{
					Severity:    "high",
					Type:        "subdomain_takeover",
					Description: fmt.Sprintf("Confirmed subdomain takeover risk: %s", subdomain),
					Details:     evidence,
				}
			}
		}()
	}

	for _, subdomain := range subset {
		jobs <- subdomain
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(out)
	}()

	findings := make([]types.Finding, 0)
	for finding := range out {
		findings = append(findings, finding)
	}

	sort.SliceStable(findings, func(i, j int) bool {
		return findings[i].Description < findings[j].Description
	})

	if len(findings) > 0 {
		result.Findings = append(result.Findings, findings...)
		markCheckFailed(result)
	}
}
