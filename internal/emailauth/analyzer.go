package emailauth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/theopenlane/sleuth/internal/intel"
)

const (
	// defaultDNSServer is the DNS resolver used when none is configured
	defaultDNSServer = "8.8.8.8:53"
	// defaultDNSTimeout is the per-query timeout for DNS lookups
	defaultDNSTimeout = 5 * time.Second

	// Weight constants for email authentication scoring
	weightMissingSPF     = 15
	weightWeakSPFPassAll = 20
	weightWeakSPFNeutral = 10
	weightMissingDMARC   = 15
	weightWeakDMARC      = 10
	weightMissingDKIM    = 10
)

// gradeThresholds for overall letter grade
const (
	gradeThresholdB = 10
	gradeThresholdC = 20
	gradeThresholdD = 30
)

// Result captures the complete email authentication analysis
type Result struct {
	// SPF holds the SPF record lookup result
	SPF SPFResult `json:"spf"`
	// DMARC holds the DMARC record lookup result
	DMARC DMARCResult `json:"dmarc"`
	// DKIM holds the DKIM selector probing result
	DKIM DKIMResult `json:"dkim"`
	// Grade is the overall email authentication grade (A/B/C/D/F)
	Grade string `json:"grade"`
}

// Analyzer performs DNS-based email authentication analysis
type Analyzer struct {
	client    *dns.Client
	dnsServer string
}

// AnalyzerOption configures the Analyzer
type AnalyzerOption func(*Analyzer)

// WithDNSServer overrides the DNS server used for lookups
func WithDNSServer(server string) AnalyzerOption {
	return func(a *Analyzer) {
		if server != "" {
			a.dnsServer = server
		}
	}
}

// WithDNSTimeout overrides the per-query DNS timeout
func WithDNSTimeout(timeout time.Duration) AnalyzerOption {
	return func(a *Analyzer) {
		if timeout > 0 {
			a.client.Timeout = timeout
		}
	}
}

// NewAnalyzer creates an email authentication analyzer
func NewAnalyzer(opts ...AnalyzerOption) *Analyzer {
	a := &Analyzer{
		client: &dns.Client{
			Timeout: defaultDNSTimeout,
		},
		dnsServer: defaultDNSServer,
	}

	for _, opt := range opts {
		opt(a)
	}

	return a
}

// Analyze performs SPF, DMARC, and DKIM analysis on the domain and returns
// a Result along with IndicatorMatch entries for the intel scoring pipeline
func (a *Analyzer) Analyze(ctx context.Context, domain string) (any, []intel.IndicatorMatch, error) {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return nil, nil, ErrEmptyDomain
	}

	spfResult := lookupSPF(ctx, a.client, a.dnsServer, domain)
	dmarcResult := lookupDMARC(ctx, a.client, a.dnsServer, domain)
	dkimResult := probeDKIM(ctx, a.client, a.dnsServer, domain)

	var matches []intel.IndicatorMatch

	if cat, weight := gradeSPF(spfResult); cat != "" && weight > 0 {
		matches = append(matches, intel.IndicatorMatch{
			Value:        domain,
			Type:         intel.IndicatorTypeDomain,
			MatchContext: fmt.Sprintf("email auth SPF: %s", spfDescription(spfResult)),
			Categories:   []string{cat},
		})
	}

	if cat, weight := gradeDMARC(dmarcResult); cat != "" && weight > 0 {
		matches = append(matches, intel.IndicatorMatch{
			Value:        domain,
			Type:         intel.IndicatorTypeDomain,
			MatchContext: fmt.Sprintf("email auth DMARC: %s", dmarcDescription(dmarcResult)),
			Categories:   []string{cat},
		})
	}

	if cat, weight := gradeDKIM(dkimResult); cat != "" && weight > 0 {
		matches = append(matches, intel.IndicatorMatch{
			Value:        domain,
			Type:         intel.IndicatorTypeDomain,
			MatchContext: "email auth DKIM: No DKIM signing detected",
			Categories:   []string{cat},
		})
	}

	totalWeight := sumWeights(spfResult, dmarcResult, dkimResult)
	grade := calculateGrade(totalWeight)

	result := Result{
		SPF:   spfResult,
		DMARC: dmarcResult,
		DKIM:  dkimResult,
		Grade: grade,
	}

	return result, matches, nil
}

// sumWeights calculates the total penalty weight across all checks
func sumWeights(spf SPFResult, dmarc DMARCResult, dkim DKIMResult) int {
	total := 0

	if _, w := gradeSPF(spf); w > 0 {
		total += w
	}

	if _, w := gradeDMARC(dmarc); w > 0 {
		total += w
	}

	if _, w := gradeDKIM(dkim); w > 0 {
		total += w
	}

	return total
}

// calculateGrade assigns a letter grade based on total penalty weight
func calculateGrade(totalWeight int) string {
	switch {
	case totalWeight == 0:
		return "A"
	case totalWeight <= gradeThresholdB:
		return "B"
	case totalWeight <= gradeThresholdC:
		return "C"
	case totalWeight <= gradeThresholdD:
		return "D"
	default:
		return "F"
	}
}
