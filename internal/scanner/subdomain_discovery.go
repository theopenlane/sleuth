package scanner

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"

	"github.com/projectdiscovery/goflags"
	subfinderrunner "github.com/projectdiscovery/subfinder/v2/pkg/runner"

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

	result.Metadata["total_subdomains"] = len(discoveredSubdomains)
	result.Metadata["subdomains"] = discoveredSubdomains
	result.Metadata["interesting_subdomains"] = interesting

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
