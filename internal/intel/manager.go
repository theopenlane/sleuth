package intel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/theopenlane/httpsling"
)

// ErrNotHydrated is returned when a scoring request is made before the feeds are hydrated.
var ErrNotHydrated = errors.New("threat intelligence feeds have not been hydrated")

// Manager coordinates downloading feeds, storing indicators, and serving lookups.
type Manager struct {
	mu              sync.RWMutex
	config          FeedConfig
	store           *indicatorStore
	httpClient      *http.Client
	storageDir      string
	logger          *log.Logger
	hydrated        bool
	lastHydrated    time.Time
	resolverTimeout time.Duration
	resolver        *net.Resolver
	dnsCache        *dnsCache
}

// Option configures the Manager.
type Option func(*Manager)

// WithStorageDir overrides the directory used to persist raw feed downloads.
func WithStorageDir(path string) Option {
	return func(m *Manager) {
		if path != "" {
			m.storageDir = path
		}
	}
}

// WithHTTPClient supplies a custom HTTP client for feed downloads.
func WithHTTPClient(client *http.Client) Option {
	return func(m *Manager) {
		if client != nil {
			m.httpClient = client
		}
	}
}

// WithLogger sets the logger used for informational messages.
func WithLogger(logger *log.Logger) Option {
	return func(m *Manager) {
		if logger != nil {
			m.logger = logger
		}
	}
}

// WithResolverTimeout configures the time limit for DNS lookups during scoring.
func WithResolverTimeout(timeout time.Duration) Option {
	return func(m *Manager) {
		if timeout > 0 {
			m.resolverTimeout = timeout
		}
	}
}

// WithResolver allows providing a custom DNS resolver.
func WithResolver(resolver *net.Resolver) Option {
	return func(m *Manager) {
		if resolver != nil {
			m.resolver = resolver
		}
	}
}

// WithDNSCacheTTL overrides the TTL used for cached DNS responses.
func WithDNSCacheTTL(ttl time.Duration) Option {
	return func(m *Manager) {
		if ttl > 0 {
			m.dnsCache = newDNSCache(ttl)
		}
	}
}

// NewManager creates an intel manager with the provided feed configuration.
func NewManager(cfg FeedConfig, opts ...Option) (*Manager, error) {
	if len(cfg.Feeds) == 0 {
		return nil, errors.New("feed configuration has no feeds defined")
	}

	manager := &Manager{
		config:     cfg,
		store:      newIndicatorStore(),
		storageDir: "data/intel",
		httpClient: &http.Client{
			Timeout: 90 * time.Second,
		},
		logger:          log.New(io.Discard, "", 0),
		resolverTimeout: 10 * time.Second,
		resolver:        net.DefaultResolver,
		dnsCache:        newDNSCache(5 * time.Minute),
	}

	for _, opt := range opts {
		opt(manager)
	}

	if manager.dnsCache == nil {
		manager.dnsCache = newDNSCache(5 * time.Minute)
	}
	if manager.resolver == nil {
		manager.resolver = net.DefaultResolver
	}

	return manager, nil
}

// LoadFeedConfig reads a feed configuration from disk.
func LoadFeedConfig(path string) (FeedConfig, error) {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return FeedConfig{}, err
	}
	defer file.Close()

	return DecodeFeedConfig(file)
}

// DecodeFeedConfig parses a feed configuration from an arbitrary reader.
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

// Hydrate downloads all known feeds concurrently and rebuilds the indicator store.
func (m *Manager) Hydrate(ctx context.Context) (HydrationSummary, error) {
	summary := HydrationSummary{
		StartedAt:  time.Now().UTC(),
		TotalFeeds: len(m.config.Feeds),
	}

	if err := os.MkdirAll(m.storageDir, 0o755); err != nil {
		return summary, fmt.Errorf("create storage dir: %w", err)
	}

	newStore := newIndicatorStore()
	var storeMu sync.Mutex
	var summaryMu sync.Mutex
	var wg sync.WaitGroup

	for _, feed := range m.config.Feeds {
		wg.Add(1)

		go func(feed Feed) {
			defer wg.Done()

			if ctx.Err() != nil {
				return
			}

			start := time.Now()
			feedSummary := FeedSummary{
				Name: feed.Name,
				URL:  feed.URL,
			}

			dest := filepath.Join(m.storageDir, feed.Name+".txt")

			storeMu.Lock()
			added, err := m.downloadAndIngest(ctx, feed, dest, newStore)
			storeMu.Unlock()

			if err != nil {
				feedSummary.Error = err.Error()
				summaryMu.Lock()
				summary.ErrorsEncountered = true
				summaryMu.Unlock()
				m.logger.Printf("intel hydrate: feed %s encountered an error: %v", feed.Name, err)
			}

			if added > 0 {
				feedSummary.Indicators = added
				feedSummary.LastUpdated = time.Now().UTC()
				summaryMu.Lock()
				summary.TotalIndicators += added
				summaryMu.Unlock()
			}

			if err == nil || added > 0 {
				feedSummary.Downloaded = true
				summaryMu.Lock()
				summary.SuccessfulFeeds++
				summaryMu.Unlock()
			} else {
				summaryMu.Lock()
				summary.FailedFeeds++
				summaryMu.Unlock()
			}

			feedSummary.Duration = time.Since(start)

			summaryMu.Lock()
			summary.Feeds = append(summary.Feeds, feedSummary)
			summaryMu.Unlock()
		}(feed)
	}

	wg.Wait()

	summary.CompletedAt = time.Now().UTC()

	m.mu.Lock()
	m.store = newStore
	m.hydrated = true
	m.lastHydrated = summary.CompletedAt
	m.mu.Unlock()

	return summary, nil
}

func (m *Manager) downloadAndIngest(ctx context.Context, feed Feed, dest string, store *indicatorStore) (int, error) {
	if err := m.fetchFeed(ctx, feed, dest); err != nil {
		// If the download failed but a cached file exists, attempt to ingest it.
		if _, statErr := os.Stat(dest); statErr == nil {
			m.logger.Printf("intel hydrate: using cached copy for %s due to download error: %v", feed.Name, err)
			added, ingestErr := store.ingestFile(dest, feed)
			if ingestErr != nil {
				return 0, fmt.Errorf("download failed (%v) and cached ingest failed: %w", err, ingestErr)
			}
			return added, fmt.Errorf("download failed, used cached copy: %w", err)
		}
		return 0, err
	}

	return store.ingestFile(dest, feed)
}

func (m *Manager) fetchFeed(ctx context.Context, feed Feed, dest string) error {
	tmp, err := os.CreateTemp(m.storageDir, feed.Name+"-*.tmp")
	if err != nil {
		return err
	}
	defer func() {
		tmp.Close()
		os.Remove(tmp.Name())
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

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	if err := tmp.Sync(); err != nil {
		return err
	}

	if err := tmp.Close(); err != nil {
		return err
	}

	return os.Rename(tmp.Name(), dest)
}

// Check evaluates an email/domain against the indicator store and returns a score.
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
				timeout = 10 * time.Second
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

	score, breakdown := calculateScore(matches)

	// Ensure deterministic ordering for response.
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
	if total > 100 {
		total = 100
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

func categoryWeight(cat string) int {
	switch cat {
	case "c2":
		return 30
	case "bot":
		return 25
	case "suspicious":
		return 20
	case "tor":
		return 15
	case "vpn":
		return 10
	case "bruteforce":
		return 15
	case "dc":
		return 5
	default:
		return 10
	}
}

func deduplicateStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	var result []string
	for _, v := range values {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		result = append(result, v)
	}
	sort.Strings(result)
	return result
}

func matchKey(match IndicatorMatch) string {
	return string(match.Type) + "|" + match.Value + "|" + match.MatchContext
}

func (m *Manager) lookupDomainIPs(ctx context.Context, domain string, timeout time.Duration) ([]net.IP, error) {
	if m.dnsCache != nil {
		return m.dnsCache.lookup(ctx, m.resolver, domain, timeout)
	}
	return resolveDomain(ctx, m.resolver, domain)
}

func buildSummary(matches []IndicatorMatch) ScoreSummary {
	if len(matches) == 0 {
		return ScoreSummary{}
	}
	feedSet := make(map[string]struct{})
	catSet := make(map[string]struct{})
	for _, match := range matches {
		for _, feed := range match.Feeds {
			if feed != "" {
				feedSet[feed] = struct{}{}
			}
		}
		for _, cat := range match.Categories {
			if cat != "" {
				catSet[strings.ToLower(cat)] = struct{}{}
			}
		}
	}
	feeds := make([]string, 0, len(feedSet))
	for feed := range feedSet {
		feeds = append(feeds, feed)
	}
	categories := make([]string, 0, len(catSet))
	for cat := range catSet {
		categories = append(categories, cat)
	}
	sort.Strings(feeds)
	sort.Strings(categories)
	return ScoreSummary{
		FeedCount:  len(feeds),
		Feeds:      feeds,
		Categories: categories,
	}
}

// calculateRiskLevel returns a risk level based on the score.
func calculateRiskLevel(score int) string {
	switch {
	case score == 0:
		return "none"
	case score <= 20:
		return "low"
	case score <= 50:
		return "medium"
	case score <= 75:
		return "high"
	default:
		return "critical"
	}
}

// calculateRecommendation returns an action recommendation based on the score.
func calculateRecommendation(score int) string {
	switch {
	case score == 0:
		return "approve"
	case score <= 20:
		return "approve"
	case score <= 50:
		return "review"
	case score <= 75:
		return "review"
	default:
		return "reject"
	}
}

// calculateRiskFlags sets boolean flags based on detected categories.
func calculateRiskFlags(categories []string) RiskFlags {
	flags := RiskFlags{}
	catSet := make(map[string]struct{})
	for _, cat := range categories {
		catSet[strings.ToLower(cat)] = struct{}{}
	}

	if _, ok := catSet["disposable"]; ok {
		flags.IsDisposableEmail = true
	}
	if _, ok := catSet["tor"]; ok {
		flags.IsTor = true
	}
	if _, ok := catSet["vpn"]; ok {
		flags.IsVPN = true
	}
	if _, ok := catSet["proxy"]; ok {
		flags.IsProxy = true
	}
	if _, ok := catSet["bot"]; ok {
		flags.IsBot = true
	}
	if _, ok := catSet["c2"]; ok {
		flags.IsC2 = true
	}
	if _, ok := catSet["spam"]; ok {
		flags.IsSpam = true
	}
	if _, ok := catSet["phishing"]; ok {
		flags.IsPhishing = true
	}
	if _, ok := catSet["malware"]; ok {
		flags.IsMalware = true
	}
	if _, ok := catSet["bruteforce"]; ok {
		flags.IsBruteforce = true
	}

	return flags
}

// buildReasons creates human-readable reasons for the score.
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
		"c2":          "Command and control infrastructure",
		"bot":         "Botnet or malicious bot activity",
		"suspicious":  "Suspicious or malicious activity",
		"tor":         "Tor network usage",
		"vpn":         "VPN service usage",
		"proxy":       "Proxy service usage",
		"bruteforce":  "Brute force attack source",
		"spam":        "Spam or unsolicited messaging",
		"phishing":    "Phishing or credential theft",
		"malware":     "Malware distribution or infection",
		"disposable":  "Disposable or temporary email service",
		"dc":          "Datacenter or hosting provider",
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

func pluralize(count int) string {
	if count == 1 {
		return ""
	}
	return "s"
}
