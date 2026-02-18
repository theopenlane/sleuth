package intel

import (
	"fmt"
	"strings"
	"time"
)

// FeedConfig represents the full set of OSINT feeds defined in feed_config.json
type FeedConfig struct {
	// Feeds holds the list of OSINT feed definitions to download and ingest
	Feeds []Feed `json:"feeds"`
}

// Feed describes a single OSINT feed to download and ingest
type Feed struct {
	// Name is the human-readable identifier for this feed
	Name string `json:"name"`
	// URL is the remote address from which the feed content is downloaded
	URL string `json:"url"`
	// Type holds the threat categories associated with this feed
	Type []string `json:"type"`
	// Indicators restricts which indicator types this feed should ingest
	Indicators []IndicatorType `json:"indicators,omitempty"`
}

// IndicatorType captures the kind of observable stored in the threat intel store
type IndicatorType string

// Supported indicator types used to classify observables in threat intel feeds
const (
	// IndicatorTypeIP is an IPv4 or IPv6 address indicator
	IndicatorTypeIP IndicatorType = "ip"
	// IndicatorTypeCIDR is a CIDR network range indicator
	IndicatorTypeCIDR IndicatorType = "cidr"
	// IndicatorTypeDomain is a domain name indicator
	IndicatorTypeDomain IndicatorType = "domain"
	// IndicatorTypeEmail is an email address indicator
	IndicatorTypeEmail IndicatorType = "email"
)

// HydrationSummary captures high-level results of a hydration run
type HydrationSummary struct {
	// StartedAt is the timestamp when the hydration run began
	StartedAt time.Time `json:"started_at"`
	// CompletedAt is the timestamp when the hydration run finished
	CompletedAt time.Time `json:"completed_at"`
	// TotalFeeds is the number of feeds that were scheduled for processing
	TotalFeeds int `json:"total_feeds"`
	// SuccessfulFeeds is the count of feeds that were downloaded and ingested without error
	SuccessfulFeeds int `json:"successful_feeds"`
	// FailedFeeds is the count of feeds that could not be downloaded or ingested
	FailedFeeds int `json:"failed_feeds"`
	// TotalIndicators is the aggregate number of indicators ingested across all feeds
	TotalIndicators int `json:"total_indicators"`
	// Feeds holds per-feed outcome details for the hydration run
	Feeds []FeedSummary `json:"feeds"`
	// ErrorsEncountered indicates whether any feed encountered an error during hydration
	ErrorsEncountered bool `json:"errors_encountered"`
}

// FeedSummary captures the outcome for an individual feed download and ingest
type FeedSummary struct {
	// Name is the identifier of the feed this summary describes
	Name string `json:"name"`
	// URL is the remote address from which the feed was downloaded
	URL string `json:"url"`
	// Downloaded indicates whether the feed content was successfully retrieved
	Downloaded bool `json:"downloaded"`
	// Indicators is the number of indicators ingested from this feed
	Indicators int `json:"indicators"`
	// UsedCachedCopy indicates that ingestion succeeded using a previously downloaded local copy
	UsedCachedCopy bool `json:"used_cached_copy,omitempty"`
	// Error holds the error message if the feed failed, empty on success
	Error string `json:"error,omitempty"`
	// Duration is the wall-clock time spent downloading and ingesting this feed
	Duration time.Duration `json:"duration"`
	// LastUpdated is the timestamp when this feed was last successfully ingested
	LastUpdated time.Time `json:"last_updated"`
}

// CheckRequest is the internal representation of a scoring request
type CheckRequest struct {
	// Email is the email address to evaluate against threat indicators
	Email string
	// Domain is the domain name to evaluate against threat indicators
	Domain string
	// IndicatorTypes restricts the lookup to specific indicator types
	IndicatorTypes []IndicatorType
	// IncludeResolvedIPs enables DNS resolution of the domain to check resolved IPs against the store
	IncludeResolvedIPs bool
}

// IndicatorMatch captures a single match against an observable
type IndicatorMatch struct {
	// Value is the raw indicator string that matched
	Value string `json:"value"`
	// Type is the classification of the matched indicator
	Type IndicatorType `json:"type"`
	// MatchContext describes how the match was found, such as the lookup path
	MatchContext string `json:"match_context"`
	// Feeds lists the feed names that contributed this indicator
	Feeds []string `json:"feeds"`
	// Categories lists the threat categories associated with this match
	Categories []string `json:"categories"`
}

// ScoreResult represents the score and supporting details
type ScoreResult struct {
	// Domain is the domain that was evaluated
	Domain string `json:"domain,omitempty"`
	// Email is the email address that was evaluated
	Email string `json:"email,omitempty"`
	// Score is the computed threat intelligence score from 0 to 100
	Score int `json:"score"`
	// RiskLevel is the qualitative risk classification derived from the score
	RiskLevel string `json:"risk_level"`
	// Recommendation is the suggested action based on the score
	Recommendation string `json:"recommendation"`
	// Reasons holds human-readable explanations for the score
	Reasons []string `json:"reasons,omitempty"`
	// Flags provides boolean indicators for common risk categories
	Flags RiskFlags `json:"flags"`
	// Matches holds the individual indicator matches that contributed to the score
	Matches []IndicatorMatch `json:"matches"`
	// CategoryBreakdown shows how each threat category contributed to the final score
	CategoryBreakdown []CategoryWeight `json:"category_breakdown"`
	// Issues records non-fatal problems encountered during the check
	Issues []string `json:"issues,omitempty"`
	// Summary provides aggregated feed and category context for the lookup
	Summary ScoreSummary `json:"summary"`
}

// RiskFlags provides boolean indicators for common risk categories
type RiskFlags struct {
	// IsDisposableEmail indicates the email address belongs to a disposable email provider
	IsDisposableEmail bool `json:"is_disposable_email"`
	// IsTor indicates the indicator is associated with the Tor network
	IsTor bool `json:"is_tor"`
	// IsVPN indicates the indicator is associated with a VPN service
	IsVPN bool `json:"is_vpn"`
	// IsProxy indicates the indicator is associated with a proxy service
	IsProxy bool `json:"is_proxy"`
	// IsBot indicates the indicator is associated with bot or botnet activity
	IsBot bool `json:"is_bot"`
	// IsC2 indicates the indicator is associated with command and control infrastructure
	IsC2 bool `json:"is_c2"`
	// IsSpam indicates the indicator is associated with spam or unsolicited messaging
	IsSpam bool `json:"is_spam"`
	// IsPhishing indicates the indicator is associated with phishing or credential theft
	IsPhishing bool `json:"is_phishing"`
	// IsMalware indicates the indicator is associated with malware distribution or infection
	IsMalware bool `json:"is_malware"`
	// IsBruteforce indicates the indicator is associated with brute force attack activity
	IsBruteforce bool `json:"is_bruteforce"`
}

// CategoryWeight records how much each category contributed to the final score
type CategoryWeight struct {
	// Category is the threat category name
	Category string `json:"category"`
	// Weight is the scoring contribution assigned to this category
	Weight int `json:"weight"`
}

// ScoreSummary captures aggregated feed and category context for a lookup
type ScoreSummary struct {
	// FeedCount is the number of distinct feeds that contributed matches
	FeedCount int `json:"feed_count"`
	// Feeds lists the distinct feed names that contributed matches
	Feeds []string `json:"feeds"`
	// Categories lists the distinct threat categories found across all matches
	Categories []string `json:"categories"`
}

// AllowsIndicatorType returns true when the feed should ingest the provided indicator type
func (f Feed) AllowsIndicatorType(t IndicatorType) bool {
	if len(f.Indicators) == 0 {
		return true
	}
	for _, allowed := range f.Indicators {
		if strings.EqualFold(string(allowed), string(t)) {
			return true
		}
	}

	return false
}

// AllowsType returns true when the request permits the supplied indicator type
func (r CheckRequest) AllowsType(t IndicatorType) bool {
	if len(r.IndicatorTypes) == 0 {
		return true
	}
	for _, allowed := range r.IndicatorTypes {
		if strings.EqualFold(string(allowed), string(t)) {
			return true
		}
	}

	return false
}

// NormalizeIndicatorTypes ensures indicator types use canonical casing and are valid
func NormalizeIndicatorTypes(types []IndicatorType) ([]IndicatorType, error) {
	if len(types) == 0 {
		return types, nil
	}

	normalized := make([]IndicatorType, 0, len(types))
	for _, t := range types {
		parsed, err := ParseIndicatorType(string(t))
		if err != nil {
			return nil, err
		}
		normalized = append(normalized, parsed)
	}

	return normalized, nil
}

// ParseIndicatorType converts a string into a recognized indicator type
func ParseIndicatorType(value string) (IndicatorType, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "ip":
		return IndicatorTypeIP, nil
	case "cidr":
		return IndicatorTypeCIDR, nil
	case "domain":
		return IndicatorTypeDomain, nil
	case "email":
		return IndicatorTypeEmail, nil
	case "":
		return "", ErrEmptyIndicatorType
	default:
		return "", fmt.Errorf("unsupported indicator type %q: %w", value, ErrEmptyIndicatorType)
	}
}
