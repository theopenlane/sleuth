package intel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/samber/lo"
	"github.com/theopenlane/httpsling"
)

const (
	// defaultRequestTimeout is the default HTTP client timeout for feed downloads
	defaultRequestTimeout = 90 * time.Second
	// defaultResolverTimeout is the default time limit for DNS lookups during scoring
	defaultResolverTimeout = 10 * time.Second
	// defaultDNSCacheTTL is the default TTL for cached DNS responses
	defaultDNSCacheTTL = 5 * time.Minute
	// maxScore is the maximum possible threat intelligence score
	maxScore = 100
	// storageDirPerm is the file mode used when creating the storage directory
	storageDirPerm = 0o755

	// Category weight constants used in threat scoring
	weightC2         = 30
	weightBot        = 25
	weightSuspicious = 20
	weightTor        = 15
	weightVPN        = 10
	weightBruteforce = 15
	weightDC         = 5
	weightDefault    = 10

	// Email authentication weight constants
	weightMissingSPF   = 15
	weightWeakSPF      = 20
	weightMissingDMARC = 15
	weightWeakDMARC    = 10
	weightMissingDKIM  = 10

	// Domain age weight constants
	weightNewDomain7d   = 25
	weightNewDomain30d  = 20
	weightNewDomain90d  = 15
	weightNewDomain365d = 10

	// Score thresholds for risk level and recommendation classification
	thresholdLow    = 20
	thresholdMedium = 50
	thresholdHigh   = 75
)

// EmailAuthAnalyzer defines the interface for email authentication analysis
type EmailAuthAnalyzer interface {
	// Analyze performs email authentication analysis on the given domain
	Analyze(ctx context.Context, domain string) (any, []IndicatorMatch, error)
}

// RDAPAnalyzer defines the interface for RDAP domain registration analysis
type RDAPAnalyzer interface {
	// Analyze performs RDAP domain registration analysis on the given domain
	Analyze(ctx context.Context, domain string) (any, []IndicatorMatch, error)
}

// Manager coordinates downloading feeds, storing indicators, and serving lookups
type Manager struct {
	// mu guards concurrent access to the Manager's mutable state
	mu sync.RWMutex
	// config holds the feed definitions used during hydration
	config FeedConfig
	// store is the in-memory indicator store built from ingested feeds
	store *indicatorStore
	// httpClient is the HTTP client used to download feed content
	httpClient *http.Client
	// storageDir is the filesystem path where raw feed downloads are persisted
	storageDir string
	// hydrated indicates whether feeds have been successfully loaded at least once
	hydrated bool
	// lastHydrated records the time of the most recent successful hydration
	lastHydrated time.Time
	// resolverTimeout is the time limit applied to DNS lookups during scoring
	resolverTimeout time.Duration
	// resolver is the DNS resolver used for domain-to-IP lookups
	resolver *net.Resolver
	// dnsCache is the TTL cache for DNS lookup results
	dnsCache *dnsCache
	// emailAuthAnalyzer is the optional email authentication analyzer
	emailAuthAnalyzer EmailAuthAnalyzer
	// rdapAnalyzer is the optional RDAP domain registration analyzer
	rdapAnalyzer RDAPAnalyzer
}

// Option configures the Manager
type Option func(*Manager)

// WithStorageDir overrides the directory used to persist raw feed downloads
func WithStorageDir(path string) Option {
	return func(m *Manager) {
		if path != "" {
			m.storageDir = path
		}
	}
}

// WithHTTPClient supplies a custom HTTP client for feed downloads
func WithHTTPClient(client *http.Client) Option {
	return func(m *Manager) {
		if client != nil {
			m.httpClient = client
		}
	}
}

// WithResolverTimeout configures the time limit for DNS lookups during scoring
func WithResolverTimeout(timeout time.Duration) Option {
	return func(m *Manager) {
		if timeout > 0 {
			m.resolverTimeout = timeout
		}
	}
}

// WithResolver allows providing a custom DNS resolver
func WithResolver(resolver *net.Resolver) Option {
	return func(m *Manager) {
		if resolver != nil {
			m.resolver = resolver
		}
	}
}

// WithDNSCacheTTL overrides the TTL used for cached DNS responses
func WithDNSCacheTTL(ttl time.Duration) Option {
	return func(m *Manager) {
		if ttl > 0 {
			m.dnsCache = newDNSCache(ttl)
		}
	}
}

// WithEmailAuthAnalyzer injects an email authentication analyzer into the Manager
func WithEmailAuthAnalyzer(a EmailAuthAnalyzer) Option {
	return func(m *Manager) {
		if a != nil {
			m.emailAuthAnalyzer = a
		}
	}
}

// WithRDAPAnalyzer injects an RDAP domain registration analyzer into the Manager
func WithRDAPAnalyzer(a RDAPAnalyzer) Option {
	return func(m *Manager) {
		if a != nil {
			m.rdapAnalyzer = a
		}
	}
}

// NewManager creates an intel manager with the provided feed configuration
func NewManager(cfg FeedConfig, opts ...Option) (*Manager, error) {
	if len(cfg.Feeds) == 0 {
		return nil, ErrNoFeedsDefined
	}

	manager := &Manager{
		config:     cfg,
		store:      newIndicatorStore(),
		storageDir: "data/intel",
		httpClient: &http.Client{
			Timeout: defaultRequestTimeout,
		},
		resolverTimeout: defaultResolverTimeout,
		resolver:        net.DefaultResolver,
		dnsCache:        newDNSCache(defaultDNSCacheTTL),
	}

	for _, opt := range opts {
		opt(manager)
	}

	if manager.dnsCache == nil {
		manager.dnsCache = newDNSCache(defaultDNSCacheTTL)
	}
	if manager.resolver == nil {
		manager.resolver = net.DefaultResolver
	}

	return manager, nil
}

// LoadFeedConfig reads a feed configuration from disk
func LoadFeedConfig(path string) (FeedConfig, error) {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return FeedConfig{}, err
	}
	defer func() { _ = file.Close() }()

	return DecodeFeedConfig(file)
}

// DecodeFeedConfig parses a feed configuration from an arbitrary reader
func DecodeFeedConfig(r io.Reader) (FeedConfig, error) {
	var cfg FeedConfig
	if err := json.NewDecoder(r).Decode(&cfg); err != nil {
		return FeedConfig{}, err
	}

	if err := cfg.normalize(); err != nil {
		return FeedConfig{}, err
	}

	return cfg, nil
}

// normalize validates and canonicalizes indicator types across all feeds in the config
func (cfg *FeedConfig) normalize() error {
	for i := range cfg.Feeds {
		normalized, err := NormalizeIndicatorTypes(cfg.Feeds[i].Indicators)
		if err != nil {
			return fmt.Errorf("feed %s: %w", cfg.Feeds[i].Name, err)
		}
		cfg.Feeds[i].Indicators = normalized
	}
	return nil
}

// Hydrate downloads all known feeds concurrently and rebuilds the indicator store
func (m *Manager) Hydrate(ctx context.Context) (HydrationSummary, error) {
	summary := HydrationSummary{
		StartedAt:  time.Now().UTC(),
		TotalFeeds: len(m.config.Feeds),
	}

	if err := os.MkdirAll(m.storageDir, storageDirPerm); err != nil {
		return summary, fmt.Errorf("create storage dir: %w", err)
	}

	newStore := newIndicatorStore()
	var summaryMu sync.Mutex
	var wg sync.WaitGroup

	for _, feed := range m.config.Feeds {
		wg.Add(1)

		go func(feed Feed) {
			defer wg.Done()

			start := time.Now()
			feedSummary := FeedSummary{
				Name: feed.Name,
				URL:  feed.URL,
			}
			defer func() {
				feedSummary.Duration = time.Since(start)
				summaryMu.Lock()
				summary.Feeds = append(summary.Feeds, feedSummary)
				summaryMu.Unlock()
			}()

			if ctx.Err() != nil {
				feedSummary.Error = ctx.Err().Error()
				summaryMu.Lock()
				summary.FailedFeeds++
				summary.ErrorsEncountered = true
				summaryMu.Unlock()
				return
			}

			dest := filepath.Join(m.storageDir, feed.Name+".txt")

			added, usedCachedCopy, err := m.downloadAndIngest(ctx, feed, dest, newStore)
			feedSummary.UsedCachedCopy = usedCachedCopy
			feedSummary.Downloaded = err == nil

			if err != nil {
				feedSummary.Error = err.Error()
				summaryMu.Lock()
				summary.ErrorsEncountered = true
				summaryMu.Unlock()
				log.Info().Msgf("intel hydrate: feed %s encountered an error: %v", feed.Name, err)
			}

			if added > 0 {
				feedSummary.Indicators = added
				feedSummary.LastUpdated = time.Now().UTC()
				summaryMu.Lock()
				summary.TotalIndicators += added
				summaryMu.Unlock()
			}

			if err == nil || added > 0 {
				summaryMu.Lock()
				summary.SuccessfulFeeds++
				summaryMu.Unlock()
			} else {
				summaryMu.Lock()
				summary.FailedFeeds++
				summaryMu.Unlock()
			}
		}(feed)
	}

	wg.Wait()

	summary.CompletedAt = time.Now().UTC()

	sort.SliceStable(summary.Feeds, func(i, j int) bool {
		return summary.Feeds[i].Name < summary.Feeds[j].Name
	})

	if err := ctx.Err(); err != nil {
		return summary, err
	}

	if newStore.indicatorCount() == 0 {
		return summary, ErrNoUsableHydrationData
	}

	m.mu.Lock()
	m.store = newStore
	m.hydrated = true
	m.lastHydrated = summary.CompletedAt
	m.mu.Unlock()

	return summary, nil
}

// downloadAndIngest fetches a feed to disk and ingests its indicators, falling back to a cached copy on download failure
func (m *Manager) downloadAndIngest(
	ctx context.Context,
	feed Feed,
	dest string,
	store *indicatorStore,
) (int, bool, error) {
	if err := m.fetchFeed(ctx, feed, dest); err != nil {
		// If the download failed but a cached file exists, attempt to ingest it
		if _, statErr := os.Stat(dest); statErr == nil {
			log.Info().Msgf("intel hydrate: using cached copy for %s due to download error: %v", feed.Name, err)
			added, ingestErr := store.ingestFile(dest, feed)
			if ingestErr != nil {
				return 0, true, fmt.Errorf("download failed (%v) and cached ingest failed: %w", err, ingestErr)
			}
			return added, true, fmt.Errorf("download failed, used cached copy: %w", err)
		}
		return 0, false, err
	}

	added, ingestErr := store.ingestFile(dest, feed)
	return added, false, ingestErr
}

// fetchFeed downloads the feed content to the destination path using an atomic temp-file rename
func (m *Manager) fetchFeed(ctx context.Context, feed Feed, dest string) error {
	tmp, err := os.CreateTemp(m.storageDir, feed.Name+"-*.tmp")
	if err != nil {
		return err
	}
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
	}()

	requester := httpsling.MustNew(
		httpsling.URL(feed.URL),
		httpsling.Method(http.MethodGet),
		httpsling.WithHTTPClient(m.httpClient),
	)

	resp, _, err := requester.ReceiveTo(ctx, tmp)
	if err != nil {
		return err
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d: %w", resp.StatusCode, ErrUnexpectedFeedStatus)
	}

	if err := tmp.Sync(); err != nil {
		return err
	}

	if err := tmp.Close(); err != nil {
		return err
	}

	return os.Rename(tmp.Name(), dest)
}

// Check evaluates an email/domain against the indicator store and returns a score
func (m *Manager) Check(ctx context.Context, req CheckRequest) (ScoreResult, error) {
	result := ScoreResult{
		Domain: strings.TrimSpace(req.Domain),
		Email:  strings.TrimSpace(req.Email),
	}

	if len(req.IndicatorTypes) > 0 {
		normalized, err := NormalizeIndicatorTypes(req.IndicatorTypes)
		if err != nil {
			return result, err
		}
		req.IndicatorTypes = normalized
	}

	m.mu.RLock()
	hydrated := m.hydrated
	store := m.store
	m.mu.RUnlock()

	if !hydrated || store == nil {
		return result, ErrNotHydrated
	}

	var matches []IndicatorMatch
	issues := make([]string, 0)

	seen := make(map[string]struct{})

	if result.Domain != "" {
		domain := strings.ToLower(result.Domain)
		for _, match := range store.matchDomain(domain) {
			if !req.AllowsType(match.Type) {
				continue
			}
			match.MatchContext = fmt.Sprintf("domain %s", domain)
			key := matchKey(match)
			if _, exists := seen[key]; !exists {
				seen[key] = struct{}{}
				matches = append(matches, match)
			}
		}

		if req.IncludeResolvedIPs && (req.AllowsType(IndicatorTypeIP) || req.AllowsType(IndicatorTypeCIDR)) {
			timeout := m.resolverTimeout
			if timeout <= 0 {
				timeout = defaultResolverTimeout
			}
			ips, err := m.lookupDomainIPs(ctx, domain, timeout)
			if err != nil {
				issues = append(issues, fmt.Sprintf("dns lookup failed for %s: %v", domain, err))
			} else {
				for _, ip := range ips {
					for _, match := range store.matchIP(ip) {
						if !req.AllowsType(match.Type) {
							continue
						}
						match.MatchContext = fmt.Sprintf("resolved IP %s for %s", ip.String(), domain)
						key := matchKey(match)
						if _, exists := seen[key]; !exists {
							seen[key] = struct{}{}
							matches = append(matches, match)
						}
					}
				}
			}
		}
	}

	if result.Email != "" {
		email := strings.ToLower(result.Email)
		for _, match := range store.matchEmail(email) {
			if !req.AllowsType(match.Type) {
				continue
			}
			match.MatchContext = fmt.Sprintf("email %s", email)
			key := matchKey(match)
			if _, exists := seen[key]; !exists {
				seen[key] = struct{}{}
				matches = append(matches, match)
			}
		}

		if at := strings.LastIndex(email, "@"); at > 0 {
			domainPart := email[at+1:]
			// Avoid duplicate domain lookup if already requested explicitly
			if domainPart != "" && !strings.EqualFold(domainPart, result.Domain) {
				reqCopy := CheckRequest{
					Domain:             domainPart,
					IndicatorTypes:     req.IndicatorTypes,
					IncludeResolvedIPs: req.IncludeResolvedIPs,
				}
				subResult, err := m.Check(ctx, reqCopy)
				if err == nil {
					for _, match := range subResult.Matches {
						if !req.AllowsType(match.Type) {
							continue
						}
						match.MatchContext = fmt.Sprintf("email domain %s", domainPart)
						key := matchKey(match)
						if _, exists := seen[key]; !exists {
							seen[key] = struct{}{}
							matches = append(matches, match)
						}
					}
					issues = append(issues, subResult.Issues...)
				} else if !errors.Is(err, ErrNotHydrated) {
					issues = append(issues, fmt.Sprintf("lookup for email domain %s failed: %v", domainPart, err))
				}
			}
		}
	}

	// Determine the domain to use for analyzer lookups
	analyzerDomain := strings.ToLower(strings.TrimSpace(result.Domain))
	if analyzerDomain == "" && result.Email != "" {
		if at := strings.LastIndex(strings.ToLower(result.Email), "@"); at > 0 {
			analyzerDomain = strings.ToLower(result.Email[at+1:])
		}
	}

	if analyzerDomain != "" {
		if m.emailAuthAnalyzer != nil {
			emailAuthResult, emailAuthMatches, err := m.emailAuthAnalyzer.Analyze(ctx, analyzerDomain)
			if err != nil {
				issues = append(issues, fmt.Sprintf("email auth analysis for %s: %v", analyzerDomain, err))
			} else {
				result.EmailAuth = emailAuthResult
				for _, match := range emailAuthMatches {
					key := matchKey(match)
					if _, exists := seen[key]; !exists {
						seen[key] = struct{}{}
						matches = append(matches, match)
					}
				}
			}
		}

		if m.rdapAnalyzer != nil {
			rdapResult, rdapMatches, err := m.rdapAnalyzer.Analyze(ctx, analyzerDomain)
			if err != nil {
				issues = append(issues, fmt.Sprintf("RDAP analysis for %s: %v", analyzerDomain, err))
			} else {
				result.DomainRegistration = rdapResult
				for _, match := range rdapMatches {
					key := matchKey(match)
					if _, exists := seen[key]; !exists {
						seen[key] = struct{}{}
						matches = append(matches, match)
					}
				}
			}
		}
	}

	score, breakdown := calculateScore(matches)

	// Ensure deterministic ordering for response
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].Type != matches[j].Type {
			return matches[i].Type < matches[j].Type
		}
		if matches[i].Value != matches[j].Value {
			return matches[i].Value < matches[j].Value
		}
		return matches[i].MatchContext < matches[j].MatchContext
	})

	result.Score = score
	result.Matches = matches
	result.CategoryBreakdown = breakdown
	if len(issues) > 0 {
		result.Issues = deduplicateStrings(issues)
	}
	result.Summary = buildSummary(matches)
	result.RiskLevel = calculateRiskLevel(score)
	result.Recommendation = calculateRecommendation(score)
	result.Flags = calculateRiskFlags(result.Summary.Categories)
	result.Reasons = buildReasons(matches, breakdown)

	return result, nil
}

// calculateScore aggregates category weights from matches and returns a capped score with a sorted breakdown
func calculateScore(matches []IndicatorMatch) (int, []CategoryWeight) {
	if len(matches) == 0 {
		return 0, nil
	}

	aggregated := make(map[string]map[string]struct{})
	for _, match := range matches {
		key := string(match.Type) + "|" + match.Value
		if _, ok := aggregated[key]; !ok {
			aggregated[key] = make(map[string]struct{})
		}
		for _, cat := range match.Categories {
			aggregated[key][strings.ToLower(cat)] = struct{}{}
		}
	}

	categoryScores := make(map[string]int)
	for _, cats := range aggregated {
		for cat := range cats {
			categoryScores[cat] += categoryWeight(cat)
		}
	}

	total := 0
	for _, weight := range categoryScores {
		total += weight
	}
	if total > maxScore {
		total = maxScore
	}

	breakdown := make([]CategoryWeight, 0, len(categoryScores))
	for cat, weight := range categoryScores {
		breakdown = append(breakdown, CategoryWeight{
			Category: cat,
			Weight:   weight,
		})
	}
	sort.SliceStable(breakdown, func(i, j int) bool {
		if breakdown[i].Weight != breakdown[j].Weight {
			return breakdown[i].Weight > breakdown[j].Weight
		}
		return breakdown[i].Category < breakdown[j].Category
	})

	return total, breakdown
}

// categoryWeight returns the scoring weight assigned to a threat category
func categoryWeight(cat string) int {
	switch cat {
	case "c2":
		return weightC2
	case "bot":
		return weightBot
	case "suspicious":
		return weightSuspicious
	case "tor":
		return weightTor
	case "vpn":
		return weightVPN
	case "bruteforce":
		return weightBruteforce
	case "dc":
		return weightDC
	case "missing_spf":
		return weightMissingSPF
	case "weak_spf":
		return weightWeakSPF
	case "missing_dmarc":
		return weightMissingDMARC
	case "weak_dmarc":
		return weightWeakDMARC
	case "missing_dkim":
		return weightMissingDKIM
	case "new_domain_7d":
		return weightNewDomain7d
	case "new_domain_30d":
		return weightNewDomain30d
	case "new_domain_90d":
		return weightNewDomain90d
	case "new_domain_365d":
		return weightNewDomain365d
	default:
		return weightDefault
	}
}

// deduplicateStrings returns a sorted slice with duplicate and empty strings removed
func deduplicateStrings(values []string) []string {
	result := lo.Uniq(lo.Compact(values))
	sort.Strings(result)
	return result
}

// matchKey produces a deduplication key from an indicator match's type, value, and context
func matchKey(match IndicatorMatch) string {
	return string(match.Type) + "|" + match.Value + "|" + match.MatchContext
}

// lookupDomainIPs resolves a domain to its IP addresses, using the DNS cache when available
func (m *Manager) lookupDomainIPs(ctx context.Context, domain string, timeout time.Duration) ([]net.IP, error) {
	if m.dnsCache != nil {
		return m.dnsCache.lookup(ctx, m.resolver, domain, timeout)
	}
	return resolveDomain(ctx, m.resolver, domain)
}

// buildSummary collects distinct feeds and categories from the matches into a ScoreSummary
func buildSummary(matches []IndicatorMatch) ScoreSummary {
	if len(matches) == 0 {
		return ScoreSummary{}
	}
	var allFeeds, allCats []string
	for _, match := range matches {
		allFeeds = append(allFeeds, match.Feeds...)
		for _, cat := range match.Categories {
			if cat != "" {
				allCats = append(allCats, strings.ToLower(cat))
			}
		}
	}
	feeds := lo.Uniq(lo.Compact(allFeeds))
	categories := lo.Uniq(allCats)
	sort.Strings(feeds)
	sort.Strings(categories)
	return ScoreSummary{
		FeedCount:  len(feeds),
		Feeds:      feeds,
		Categories: categories,
	}
}

// calculateRiskLevel returns a risk level based on the score
func calculateRiskLevel(score int) string {
	switch {
	case score == 0:
		return "none"
	case score <= thresholdLow:
		return "low"
	case score <= thresholdMedium:
		return "medium"
	case score <= thresholdHigh:
		return "high"
	default:
		return "critical"
	}
}

// calculateRecommendation returns an action recommendation based on the score
func calculateRecommendation(score int) string {
	switch {
	case score == 0:
		return "approve"
	case score <= thresholdLow:
		return "approve"
	case score <= thresholdMedium:
		return "review"
	case score <= thresholdHigh:
		return "review"
	default:
		return "reject"
	}
}

// calculateRiskFlags sets boolean flags based on detected categories
func calculateRiskFlags(categories []string) RiskFlags {
	lower := lo.Map(categories, func(c string, _ int) string { return strings.ToLower(c) })
	return RiskFlags{
		IsDisposableEmail: lo.Contains(lower, "disposable"),
		IsTor:             lo.Contains(lower, "tor"),
		IsVPN:             lo.Contains(lower, "vpn"),
		IsProxy:           lo.Contains(lower, "proxy"),
		IsBot:             lo.Contains(lower, "bot"),
		IsC2:              lo.Contains(lower, "c2"),
		IsSpam:            lo.Contains(lower, "spam"),
		IsPhishing:        lo.Contains(lower, "phishing"),
		IsMalware:         lo.Contains(lower, "malware"),
		IsBruteforce:      lo.Contains(lower, "bruteforce"),
		IsNewDomain:       containsAny(lower, "new_domain_7d", "new_domain_30d", "new_domain_90d", "new_domain_365d"),
		IsWeakEmailAuth:   containsAny(lower, "missing_spf", "weak_spf", "missing_dmarc", "weak_dmarc", "missing_dkim"),
	}
}

// containsAny returns true if the slice contains any of the provided values
func containsAny(slice []string, values ...string) bool {
	for _, v := range values {
		if lo.Contains(slice, v) {
			return true
		}
	}

	return false
}

// buildReasons creates human-readable reasons for the score
func buildReasons(matches []IndicatorMatch, breakdown []CategoryWeight) []string {
	if len(matches) == 0 {
		return nil
	}

	reasons := make([]string, 0)
	catMap := make(map[string]int)
	for _, cw := range breakdown {
		catMap[cw.Category] = cw.Weight
	}

	catCounts := make(map[string]int)
	for _, match := range matches {
		for _, cat := range match.Categories {
			catCounts[strings.ToLower(cat)]++
		}
	}

	categoryDescriptions := map[string]string{
		"c2":              "Command and control infrastructure",
		"bot":             "Botnet or malicious bot activity",
		"suspicious":      "Suspicious or malicious activity",
		"tor":             "Tor network usage",
		"vpn":             "VPN service usage",
		"proxy":           "Proxy service usage",
		"bruteforce":      "Brute force attack source",
		"spam":            "Spam or unsolicited messaging",
		"phishing":        "Phishing or credential theft",
		"malware":         "Malware distribution or infection",
		"disposable":      "Disposable or temporary email service",
		"dc":              "Datacenter or hosting provider",
		"missing_spf":     "No SPF record configured",
		"weak_spf":        "SPF policy is too permissive",
		"missing_dmarc":   "No DMARC record configured",
		"weak_dmarc":      "DMARC policy set to none (monitoring only)",
		"missing_dkim":    "No DKIM signing detected",
		"new_domain_7d":   "Domain registered within the last 7 days",
		"new_domain_30d":  "Domain registered within the last 30 days",
		"new_domain_90d":  "Domain registered within the last 90 days",
		"new_domain_365d": "Domain registered within the last year",
	}

	for _, cw := range breakdown {
		if count, ok := catCounts[cw.Category]; ok && count > 0 {
			desc := categoryDescriptions[cw.Category]
			if desc == "" {
				desc = cw.Category
			}
			reasons = append(reasons, fmt.Sprintf("%s detected (%d indicator%s, weight: %d)",
				desc, count, pluralize(count), cw.Weight))
		}
	}

	return reasons
}

// pluralize returns "s" when count is not 1, for use in human-readable messages
func pluralize(count int) string {
	if count == 1 {
		return ""
	}
	return "s"
}
