package intel

import (
	"fmt"
	"strings"
	"time"
)

// FeedConfig represents the full set of OSINT feeds defined in feed_config.json.
type FeedConfig struct {
	Feeds []Feed `json:"feeds"`
}

// Feed describes a single OSINT feed to download and ingest.
type Feed struct {
	Name       string          `json:"name"`
	URL        string          `json:"url"`
	Type       []string        `json:"type"`
	Indicators []IndicatorType `json:"indicators,omitempty"`
}

// IndicatorType captures the kind of observable stored in the threat intel store.
type IndicatorType string

const (
	IndicatorTypeIP     IndicatorType = "ip"
	IndicatorTypeCIDR   IndicatorType = "cidr"
	IndicatorTypeDomain IndicatorType = "domain"
	IndicatorTypeEmail  IndicatorType = "email"
)

// HydrationSummary captures high-level results of a hydration run.
type HydrationSummary struct {
	StartedAt         time.Time     `json:"started_at"`
	CompletedAt       time.Time     `json:"completed_at"`
	TotalFeeds        int           `json:"total_feeds"`
	SuccessfulFeeds   int           `json:"successful_feeds"`
	FailedFeeds       int           `json:"failed_feeds"`
	TotalIndicators   int           `json:"total_indicators"`
	Feeds             []FeedSummary `json:"feeds"`
	ErrorsEncountered bool          `json:"errors_encountered"`
}

// FeedSummary captures the outcome for an individual feed download and ingest.
type FeedSummary struct {
	Name        string        `json:"name"`
	URL         string        `json:"url"`
	Downloaded  bool          `json:"downloaded"`
	Indicators  int           `json:"indicators"`
	Error       string        `json:"error,omitempty"`
	Duration    time.Duration `json:"duration"`
	LastUpdated time.Time     `json:"last_updated"`
}

// CheckRequest is the internal representation of a scoring request.
type CheckRequest struct {
	Email              string
	Domain             string
	IndicatorTypes     []IndicatorType
	IncludeResolvedIPs bool
}

// IndicatorMatch captures a single match against an observable.
type IndicatorMatch struct {
	Value        string        `json:"value"`
	Type         IndicatorType `json:"type"`
	MatchContext string        `json:"match_context"`
	Feeds        []string      `json:"feeds"`
	Categories   []string      `json:"categories"`
}

// ScoreResult represents the score and supporting details.
type ScoreResult struct {
	Domain            string           `json:"domain,omitempty"`
	Email             string           `json:"email,omitempty"`
	Score             int              `json:"score"`
	RiskLevel         string           `json:"risk_level"`
	Recommendation    string           `json:"recommendation"`
	Reasons           []string         `json:"reasons,omitempty"`
	Flags             RiskFlags        `json:"flags"`
	Matches           []IndicatorMatch `json:"matches"`
	CategoryBreakdown []CategoryWeight `json:"category_breakdown"`
	Issues            []string         `json:"issues,omitempty"`
	Summary           ScoreSummary     `json:"summary"`
}

// RiskFlags provides boolean indicators for common risk categories.
type RiskFlags struct {
	IsDisposableEmail bool `json:"is_disposable_email"`
	IsTor             bool `json:"is_tor"`
	IsVPN             bool `json:"is_vpn"`
	IsProxy           bool `json:"is_proxy"`
	IsBot             bool `json:"is_bot"`
	IsC2              bool `json:"is_c2"`
	IsSpam            bool `json:"is_spam"`
	IsPhishing        bool `json:"is_phishing"`
	IsMalware         bool `json:"is_malware"`
	IsBruteforce      bool `json:"is_bruteforce"`
}

// CategoryWeight records how much each category contributed to the final score.
type CategoryWeight struct {
	Category string `json:"category"`
	Weight   int    `json:"weight"`
}

// ScoreSummary captures aggregated feed and category context for a lookup.
type ScoreSummary struct {
	FeedCount  int      `json:"feed_count"`
	Feeds      []string `json:"feeds"`
	Categories []string `json:"categories"`
}

// AllowsIndicatorType returns true when the feed should ingest the provided indicator type.
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

// AllowsType returns true when the request permits the supplied indicator type.
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

// NormalizeIndicatorTypes ensures indicator types use canonical casing and are valid.
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

// ParseIndicatorType converts a string into a recognized indicator type.
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
		return "", fmt.Errorf("indicator type cannot be empty")
	default:
		return "", fmt.Errorf("unsupported indicator type %q", value)
	}
}
