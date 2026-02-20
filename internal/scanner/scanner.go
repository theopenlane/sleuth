package scanner

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/rs/zerolog/log"

	"github.com/theopenlane/sleuth/internal/domain"
	"github.com/theopenlane/sleuth/internal/types"
)

const (
	// orderDNSAnalysis is the display order for DNS analysis results.
	orderDNSAnalysis = 0
	// orderSubdomainDiscovery is the display order for subdomain discovery results.
	orderSubdomainDiscovery = 1
	// orderHTTPAnalysis is the display order for HTTP analysis results.
	orderHTTPAnalysis = 2
	// orderTechnologyDetection is the display order for technology detection results.
	orderTechnologyDetection = 3
	// orderNucleiScan is the display order for nuclei scan results.
	orderNucleiScan = 4
)

var checkResultOrder = map[string]int{
	"dns_analysis":         orderDNSAnalysis,
	"subdomain_discovery":  orderSubdomainDiscovery,
	"http_analysis":        orderHTTPAnalysis,
	"technology_detection": orderTechnologyDetection,
	"nuclei_scan":          orderNucleiScan,
}

// Scanner performs comprehensive domain analysis.
type Scanner struct {
	// options holds the configuration for scan behavior.
	options *ScanOptions
	// nucleiEngine is a pre-initialized, thread-safe nuclei engine that persists
	// across scans to avoid per-request template loading and initialization overhead.
	nucleiEngine *nuclei.ThreadSafeNucleiEngine
}

// New creates a new scanner with the given options.
func New(opts ...ScanOption) (*Scanner, error) {
	options := DefaultScanOptions()
	for _, opt := range opts {
		opt(options)
	}

	s := &Scanner{
		options: options,
	}

	if len(options.NucleiSeverity) > 0 {
		ne, err := s.initNucleiEngine()
		if err != nil {
			log.Warn().Err(err).Msg("nuclei engine pre-initialization failed, nuclei scanning disabled")
		} else {
			s.nucleiEngine = ne
			log.Info().Msg("nuclei engine pre-initialized")
		}
	}

	return s, nil
}

// ScanDomain performs comprehensive domain analysis.
func (s *Scanner) ScanDomain(ctx context.Context, domainName string) (*types.ScanResult, error) {
	info, err := domain.Parse(domainName)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidDomain, err)
	}

	result := &types.ScanResult{
		Domain:    info.Domain,
		ScannedAt: fmt.Sprintf("%d", time.Now().Unix()),
		DomainInfo: &types.DomainInfo{
			Domain:    info.Domain,
			Subdomain: info.Subdomain,
			TLD:       info.TLD,
			SLD:       info.SLD,
		},
		Results: make([]types.CheckResult, 0),
	}

	// resultBufSize is the buffer size for the scan results channel.
	const resultBufSize = 10

	resultsChan := make(chan types.CheckResult, resultBufSize)
	var wg sync.WaitGroup

	wg.Go(func() {
		start := time.Now()
		if dnsResult := s.performDNSAnalysis(ctx, info.Domain); dnsResult != nil {
			resultsChan <- *dnsResult
		}
		log.Info().Str("domain", info.Domain).Dur("elapsed", time.Since(start)).Msg("dns analysis complete")
	})
	wg.Go(func() {
		start := time.Now()
		if subResult := s.performSubdomainDiscovery(ctx, info.Domain); subResult != nil {
			resultsChan <- *subResult
		}
		log.Info().Str("domain", info.Domain).Dur("elapsed", time.Since(start)).Msg("subdomain discovery complete")
	})
	wg.Go(func() {
		start := time.Now()
		if httpResult := s.performHTTPAnalysis(ctx, info.Domain); httpResult != nil {
			resultsChan <- *httpResult
		}
		log.Info().Str("domain", info.Domain).Dur("elapsed", time.Since(start)).Msg("http analysis complete")
	})
	wg.Go(func() {
		start := time.Now()
		if techResult := s.performTechnologyDetection(ctx, info.Domain); techResult != nil {
			resultsChan <- *techResult
		}
		log.Info().Str("domain", info.Domain).Dur("elapsed", time.Since(start)).Msg("technology detection complete")
	})

	if s.nucleiEngine != nil {
		wg.Go(func() {
			start := time.Now()
			if nucleiResult := s.performNucleiScan(ctx, info.Domain); nucleiResult != nil {
				resultsChan <- *nucleiResult
			}
			log.Info().Str("domain", info.Domain).Dur("elapsed", time.Since(start)).Msg("nuclei scan complete")
		})
	}

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	for checkResult := range resultsChan {
		result.Results = append(result.Results, checkResult)
	}

	mergeServicesIntoTechnology(result)

	sort.SliceStable(result.Results, func(i, j int) bool {
		iOrder, iOk := checkResultOrder[result.Results[i].CheckName]
		jOrder, jOk := checkResultOrder[result.Results[j].CheckName]
		switch {
		case iOk && jOk:
			return iOrder < jOrder
		case iOk:
			return true
		case jOk:
			return false
		default:
			return result.Results[i].CheckName < result.Results[j].CheckName
		}
	})

	return result, nil
}

// subdomainPlatformMap maps interesting subdomain page titles (lowercased) to
// the SaaS platform that typically powers them.
var subdomainPlatformMap = map[string]string{
	"instatus":     "Instatus",
	"statuspage":   "Atlassian Statuspage",
	"atlassian":    "Atlassian Statuspage",
	"vanta":        "Vanta",
	"vanta trust":  "Vanta",
	"safebase":     "SafeBase",
	"drata":        "Drata",
	"secureframe":  "Secureframe",
	"trustpage":    "TrustPage",
	"conveyor":     "Conveyor",
	"betteruptime": "Better Uptime",
	"freshstatus":  "Freshstatus",
	"cachet":       "Cachet",
	"upptime":      "Upptime",
	"pagerduty":    "PagerDuty",
	"opsgenie":     "Opsgenie",
	"zendesk":      "Zendesk",
	"intercom":     "Intercom",
	"freshdesk":    "Freshdesk",
	"helpscout":    "Help Scout",
	"notion":       "Notion",
	"gitbook":      "GitBook",
	"readme":       "ReadMe",
	"docusaurus":   "Docusaurus",
	"ghost":        "Ghost",
	"wordpress":    "WordPress",
	"webflow":      "Webflow",
	"hubspot":      "HubSpot",
	"shopify":      "Shopify",
	"squarespace":  "Squarespace",
	"wix":          "Wix",
}

// serviceWebsiteMap maps service/platform names to their website URLs for favicon resolution.
var serviceWebsiteMap = map[string]string{
	"Google Workspace":     "https://workspace.google.com",
	"Facebook / Meta":      "https://meta.com",
	"Apple":                "https://apple.com",
	"Slack":                "https://slack.com",
	"HubSpot":              "https://hubspot.com",
	"Atlassian":            "https://atlassian.com",
	"DocuSign":             "https://docusign.com",
	"Stripe":               "https://stripe.com",
	"Zoom":                 "https://zoom.us",
	"Miro":                 "https://miro.com",
	"Microsoft 365":        "https://microsoft.com",
	"Cisco Webex":          "https://webex.com",
	"Have I Been Pwned":    "https://haveibeenpwned.com",
	"Adobe":                "https://adobe.com",
	"Cloudflare":           "https://cloudflare.com",
	"Brevo":                "https://brevo.com",
	"Intercom":             "https://intercom.com",
	"Pinterest":            "https://pinterest.com",
	"Duo Security":         "https://duo.com",
	"1Password":            "https://1password.com",
	"KnowBe4":              "https://knowbe4.com",
	"Calendly":             "https://calendly.com",
	"Postman":              "https://postman.com",
	"LogMeIn":              "https://logmein.com",
	"OneTrust":             "https://onetrust.com",
	"Sophos":               "https://sophos.com",
	"Drift":                "https://drift.com",
	"Yandex":               "https://yandex.com",
	"Instatus":             "https://instatus.com",
	"Atlassian Statuspage": "https://statuspage.io",
	"Vanta":                "https://vanta.com",
	"SafeBase":             "https://safebase.io",
	"Drata":                "https://drata.com",
	"Secureframe":          "https://secureframe.com",
	"TrustPage":            "https://trustpage.io",
	"Conveyor":             "https://conveyor.com",
	"Better Uptime":        "https://betteruptime.com",
	"Freshstatus":          "https://freshstatus.io",
	"Cachet":               "https://cachethq.io",
	"Upptime":              "https://upptime.js.org",
	"PagerDuty":            "https://pagerduty.com",
	"Opsgenie":             "https://opsgenie.com",
	"Zendesk":              "https://zendesk.com",
	"Freshdesk":            "https://freshdesk.com",
	"Help Scout":           "https://helpscout.com",
	"Notion":               "https://notion.so",
	"GitBook":              "https://gitbook.com",
	"ReadMe":               "https://readme.com",
	"Docusaurus":           "https://docusaurus.io",
	"Ghost":                "https://ghost.org",
	"WordPress":            "https://wordpress.org",
	"Webflow":              "https://webflow.com",
	"Shopify":              "https://shopify.com",
	"Squarespace":          "https://squarespace.com",
	"Wix":                  "https://wix.com",
}

// lookupServiceWebsite performs a case-insensitive lookup against serviceWebsiteMap.
// This handles provider names from cdncheck (lowercase, e.g. "cloudflare") matching
// against map keys with standard casing (e.g. "Cloudflare").
func lookupServiceWebsite(name string) string {
	if url, ok := serviceWebsiteMap[name]; ok {
		return url
	}

	lower := strings.ToLower(name)
	for k, v := range serviceWebsiteMap {
		if strings.ToLower(k) == lower {
			return v
		}
	}

	return ""
}

// mergeServicesIntoTechnology copies service_detection findings from dns_analysis
// and platform detections from interesting subdomains into the technology_detection check.
func mergeServicesIntoTechnology(result *types.ScanResult) {
	var dnsCheck, subCheck, techCheck *types.CheckResult

	for i := range result.Results {
		switch result.Results[i].CheckName {
		case "dns_analysis":
			dnsCheck = &result.Results[i]
		case "subdomain_discovery":
			subCheck = &result.Results[i]
		case "technology_detection":
			techCheck = &result.Results[i]
		}
	}

	if techCheck == nil {
		return
	}

	existing, _ := techCheck.Metadata["detected_technologies"].([]TechnologyDetail)
	seen := make(map[string]bool, len(existing))

	for _, t := range existing {
		seen[strings.ToLower(t.Name)] = true
	}

	// Merge DNS TXT verification services
	if dnsCheck != nil {
		services, _ := dnsCheck.Metadata["detected_services"].([]string)
		for _, svc := range services {
			if seen[strings.ToLower(svc)] {
				continue
			}

			seen[strings.ToLower(svc)] = true

			existing = append(existing, TechnologyDetail{
				Name:        svc,
				Categories:  []string{"SaaS"},
				Website:     lookupServiceWebsite(svc),
				Description: "Confirmed via domain verification TXT record",
				Source:      "dns",
			})

			techCheck.Findings = append(techCheck.Findings, types.Finding{
				Severity:    "info",
				Type:        "technology",
				Description: fmt.Sprintf("Service: %s", svc),
				Details:     "Detected via DNS TXT domain verification record",
			})
		}
	}

	// Merge infrastructure providers (CDN, cloud, WAF)
	infraProviders, _ := techCheck.Metadata["infrastructure_providers"].([]InfrastructureProvider)
	for _, infra := range infraProviders {
		if seen[strings.ToLower(infra.Provider)] {
			continue
		}

		seen[strings.ToLower(infra.Provider)] = true

		existing = append(existing, TechnologyDetail{
			Name:        infra.Provider,
			Categories:  []string{strings.ToUpper(infra.Category)},
			Website:     lookupServiceWebsite(infra.Provider),
			Description: infra.Details,
			Source:      "infrastructure",
		})
	}

	// Merge interesting subdomain platform detections
	if subCheck != nil {
		details, _ := subCheck.Metadata["interesting_subdomain_details"].([]InterestingSubdomainInfo)
		for _, d := range details {
			if !d.Live || d.Title == "" {
				continue
			}

			platform := identifyPlatform(d.Title)
			if platform == "" || seen[strings.ToLower(platform)] {
				continue
			}

			seen[strings.ToLower(platform)] = true

			existing = append(existing, TechnologyDetail{
				Name:        platform,
				Categories:  []string{"SaaS"},
				Website:     lookupServiceWebsite(platform),
				Description: fmt.Sprintf("Detected on %s (%s)", d.Subdomain, d.Context),
				Source:      "subdomain",
			})

			techCheck.Findings = append(techCheck.Findings, types.Finding{
				Severity:    "info",
				Type:        "technology",
				Description: fmt.Sprintf("Service: %s", platform),
				Details:     fmt.Sprintf("Detected via subdomain %s (page title: %s)", d.Subdomain, d.Title),
			})
		}
	}

	sort.Slice(existing, func(i, j int) bool {
		return existing[i].Name < existing[j].Name
	})

	techCheck.Metadata["detected_technologies"] = existing
}

// identifyPlatform attempts to match a page title to a known SaaS platform.
func identifyPlatform(title string) string {
	lower := strings.ToLower(title)

	for keyword, platform := range subdomainPlatformMap {
		if strings.Contains(lower, keyword) {
			return platform
		}
	}

	return ""
}

// Close cleans up scanner resources.
func (s *Scanner) Close() error {
	if s.nucleiEngine != nil {
		s.nucleiEngine.Close()
	}

	return nil
}
