package scanner

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"

	"github.com/projectdiscovery/cdncheck"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"

	"github.com/theopenlane/sleuth/internal/types"
)

// techHTTPReadLimit caps how many response bytes are read for wappalyzer fingerprinting.
const techHTTPReadLimit = 100 * 1024

// TechnologyDetail holds enriched information about a detected technology.
type TechnologyDetail struct {
	// Name is the technology name as identified by wappalyzer.
	Name string `json:"name"`
	// Categories lists the wappalyzer categories for this technology.
	Categories []string `json:"categories,omitempty"`
	// Website is the official website URL for the technology.
	Website string `json:"website,omitempty"`
	// Description is a brief description of the technology.
	Description string `json:"description,omitempty"`
	// Source indicates how the technology was detected (e.g. "wappalyzer", "dns", "subdomain").
	Source string `json:"source,omitempty"`
}

// excludedTechnologyNames lists protocol features and web standards that are
// not vendor or SaaS technologies and should be excluded from results.
var excludedTechnologyNames = map[string]struct{}{
	"HTTP/2":            {},
	"HTTP/3":            {},
	"QUIC":              {},
	"HSTS":              {},
	"Open Graph":        {},
	"Twitter Cards":     {},
	"Schema.org":        {},
	"JSON-LD":           {},
	"Meta Tags":         {},
	"WebP":              {},
	"Webpack":           {},
	"Vite":              {},
	"Module Federation": {},
}

// performTechnologyDetection identifies technologies used by the domain
// via CNAME/IP infrastructure detection and HTTP-based wappalyzer fingerprinting.
func (s *Scanner) performTechnologyDetection(ctx context.Context, domain string) *types.CheckResult {
	result := newCheckResult("technology_detection")
	s.detectInfrastructure(ctx, domain, result)
	s.fingerprintHTTPTechnologies(ctx, domain, result)

	return result
}

// fingerprintHTTPTechnologies makes an HTTP GET to the domain and runs wappalyzer
// fingerprinting against the response headers and body.
func (s *Scanner) fingerprintHTTPTechnologies(ctx context.Context, domain string, result *types.CheckResult) {
	client := &http.Client{
		Timeout: s.options.HTTPTimeout,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= httpRedirectLimit {
				return ErrTooManyRedirects
			}

			return nil
		},
	}

	var resp *http.Response

	for _, scheme := range []string{"https", "http"} {
		url := fmt.Sprintf("%s://%s", scheme, domain)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Sleuth/1.0)")

		resp, err = client.Do(req)
		if err != nil {
			continue
		}

		break
	}

	if resp == nil {
		return
	}

	defer func() { _ = resp.Body.Close() }()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, techHTTPReadLimit))
	if err != nil {
		return
	}

	s.detectTechnologies(string(bodyBytes), resp.Header, result)
}

// detectTechnologies identifies technologies from HTTP headers and body content
// using wappalyzer fingerprinting with enriched metadata. Non-vendor detections
// (protocol features, web standards) are filtered out.
func (s *Scanner) detectTechnologies(body string, headers http.Header, result *types.CheckResult) {
	client, err := wappalyzer.New()
	if err != nil {
		result.Findings = append(result.Findings, types.Finding{
			Severity:    "info",
			Type:        "technology_error",
			Description: fmt.Sprintf("Technology fingerprinting failed: %v", err),
		})
		return
	}

	fingerprints := client.FingerprintWithInfo(headers, []byte(body))
	technologies := make([]TechnologyDetail, 0, len(fingerprints))

	for tech, info := range fingerprints {
		if _, excluded := excludedTechnologyNames[tech]; excluded {
			continue
		}

		detail := TechnologyDetail{
			Name:        tech,
			Categories:  info.Categories,
			Website:     info.Website,
			Description: info.Description,
			Source:      "wappalyzer",
		}

		technologies = append(technologies, detail)

		result.Findings = append(result.Findings, types.Finding{
			Severity:    "info",
			Type:        "technology",
			Description: fmt.Sprintf("Technology: %s", tech),
			Details:     info.Description,
		})
	}

	sort.Slice(technologies, func(i, j int) bool {
		return technologies[i].Name < technologies[j].Name
	})

	result.Metadata["detected_technologies"] = technologies
}

// InfrastructureProvider holds a detected infrastructure provider (CDN, cloud, WAF).
type InfrastructureProvider struct {
	// Provider is the infrastructure provider name (e.g. "Cloudflare", "Amazon")
	Provider string `json:"provider"`
	// Category is the infrastructure type (e.g. "cdn", "cloud", "waf")
	Category string `json:"category"`
	// Details describes how the provider was detected
	Details string `json:"details"`
}

// detectInfrastructure detects CDN, cloud provider, and WAF using cdncheck.
// Detected providers are stored in metadata for later merging into detected_technologies.
func (s *Scanner) detectInfrastructure(ctx context.Context, domain string, result *types.CheckResult) {
	client := cdncheck.New()
	seen := make(map[string]bool)
	resolver := net.DefaultResolver
	var providers []InfrastructureProvider

	dnsCtx, cancel := s.withDNSTimeout(ctx)
	defer cancel()

	if cname, err := resolver.LookupCNAME(dnsCtx, domain); err == nil && cname != domain+"." {
		cnameClean := strings.TrimSuffix(cname, ".")
		if matched, provider, itemType, checkErr := client.CheckSuffix(cnameClean); matched && checkErr == nil && provider != "" {
			key := fmt.Sprintf("%s:%s", provider, itemType)
			if !seen[key] {
				seen[key] = true
				details := fmt.Sprintf("CNAME points to %s", cnameClean)

				result.Findings = append(result.Findings, types.Finding{
					Severity:    "info",
					Type:        "technology",
					Description: fmt.Sprintf("%s: %s", itemType, provider),
					Details:     details,
				})

				providers = append(providers, InfrastructureProvider{
					Provider: provider,
					Category: itemType,
					Details:  details,
				})
			}
		}
	}

	if ips, err := resolver.LookupIP(dnsCtx, "ip", domain); err == nil && len(ips) > 0 {
		for _, ip := range ips {
			matched, provider, itemType, checkErr := client.Check(ip)
			if checkErr == nil && matched && provider != "" {
				key := fmt.Sprintf("%s:%s", provider, itemType)
				if seen[key] {
					continue
				}

				seen[key] = true
				details := fmt.Sprintf("IP %s belongs to %s", ip.String(), provider)

				result.Findings = append(result.Findings, types.Finding{
					Severity:    "info",
					Type:        "technology",
					Description: fmt.Sprintf("%s: %s", itemType, provider),
					Details:     details,
				})

				providers = append(providers, InfrastructureProvider{
					Provider: provider,
					Category: itemType,
					Details:  details,
				})
			}
		}
	}

	if len(providers) > 0 {
		result.Metadata["infrastructure_providers"] = providers
	}
}
