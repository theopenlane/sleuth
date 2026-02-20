package rdap

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	rdaplib "github.com/openrdap/rdap"

	"github.com/theopenlane/sleuth/internal/intel"
)

const (
	// defaultTimeout is the default timeout for RDAP queries
	defaultTimeout = 30 * time.Second

	// hoursPerDay is the number of hours in a day for age calculation
	hoursPerDay = 24

	// Domain age thresholds in days
	thresholdDays7   = 7
	thresholdDays30  = 30
	thresholdDays90  = 90
	thresholdDays365 = 365

	// Weight constants for domain age scoring
	weightNewDomain7d   = 25
	weightNewDomain30d  = 20
	weightNewDomain90d  = 15
	weightNewDomain365d = 10
)

// Result captures the RDAP domain registration analysis
type Result struct {
	// Domain is the domain that was queried
	Domain string `json:"domain"`
	// RegistrationDate is when the domain was first registered
	RegistrationDate *time.Time `json:"registration_date,omitempty"`
	// ExpirationDate is when the domain registration expires
	ExpirationDate *time.Time `json:"expiration_date,omitempty"`
	// LastChanged is when the domain record was last modified
	LastChanged *time.Time `json:"last_changed,omitempty"`
	// Registrar is the name of the registrar
	Registrar string `json:"registrar,omitempty"`
	// Status lists the domain status values from RDAP
	Status []string `json:"status,omitempty"`
	// DomainAgeDays is the number of days since registration
	DomainAgeDays int `json:"domain_age_days"`
	// DNSSEC indicates whether DNSSEC is enabled
	DNSSEC bool `json:"dnssec"`
}

// Client wraps the openrdap library for domain registration analysis
type Client struct {
	rdapClient *rdaplib.Client
	timeout    time.Duration
}

// ClientOption configures the Client
type ClientOption func(*Client)

// WithHTTPClient overrides the HTTP client used for RDAP queries
func WithHTTPClient(httpClient *http.Client) ClientOption {
	return func(c *Client) {
		if httpClient != nil {
			c.rdapClient.HTTP = httpClient
		}
	}
}

// WithTimeout overrides the timeout for RDAP queries
func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *Client) {
		if timeout > 0 {
			c.timeout = timeout
		}
	}
}

// NewClient creates an RDAP client for domain registration analysis
func NewClient(opts ...ClientOption) *Client {
	c := &Client{
		rdapClient: &rdaplib.Client{},
		timeout:    defaultTimeout,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// Analyze performs an RDAP lookup on the domain and returns a Result
// along with IndicatorMatch entries for the intel scoring pipeline
func (c *Client) Analyze(ctx context.Context, domain string) (any, []intel.IndicatorMatch, error) {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return nil, nil, ErrEmptyDomain
	}

	req := &rdaplib.Request{
		Type:    rdaplib.DomainRequest,
		Query:   domain,
		Timeout: c.timeout,
	}

	req = req.WithContext(ctx)

	resp, err := c.rdapClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("RDAP query for %s: %w", domain, err)
	}

	domainObj, ok := resp.Object.(*rdaplib.Domain)
	if !ok || domainObj == nil {
		return nil, nil, fmt.Errorf("RDAP query for %s returned unexpected type: %w", domain, ErrNoRegistrationDate)
	}

	result := buildResult(domain, domainObj)
	matches := buildMatches(domain, result)

	return result, matches, nil
}

// buildResult extracts registration data from the RDAP domain response
func buildResult(domain string, d *rdaplib.Domain) Result {
	result := Result{
		Domain: domain,
		Status: d.Status,
	}

	for _, event := range d.Events {
		parsed, err := time.Parse(time.RFC3339, event.Date)
		if err != nil {
			continue
		}

		t := parsed
		switch strings.ToLower(event.Action) {
		case "registration":
			result.RegistrationDate = &t
		case "expiration":
			result.ExpirationDate = &t
		case "last changed":
			result.LastChanged = &t
		}
	}

	if result.RegistrationDate != nil {
		result.DomainAgeDays = int(time.Since(*result.RegistrationDate).Hours() / hoursPerDay)
	}

	if d.SecureDNS != nil && d.SecureDNS.DelegationSigned != nil {
		result.DNSSEC = *d.SecureDNS.DelegationSigned
	}

	for _, entity := range d.Entities {
		for _, role := range entity.Roles {
			if strings.EqualFold(role, "registrar") {
				if entity.VCard != nil {
					result.Registrar = entity.VCard.Name()
				} else if entity.Handle != "" {
					result.Registrar = entity.Handle
				}

				break
			}
		}
	}

	return result
}

// buildMatches creates IndicatorMatch entries based on domain age
func buildMatches(domain string, result Result) []intel.IndicatorMatch {
	if result.RegistrationDate == nil {
		return nil
	}

	cat, weight := gradeDomainAge(result.DomainAgeDays)
	if cat == "" || weight == 0 {
		return nil
	}

	return []intel.IndicatorMatch{
		{
			Value:        domain,
			Type:         intel.IndicatorTypeDomain,
			MatchContext: fmt.Sprintf("domain age: %d days (registered %s)", result.DomainAgeDays, result.RegistrationDate.Format(time.DateOnly)),
			Categories:   []string{cat},
		},
	}
}

// gradeDomainAge returns the most specific category and weight for a domain age
func gradeDomainAge(ageDays int) (string, int) {
	switch {
	case ageDays < thresholdDays7:
		return "new_domain_7d", weightNewDomain7d
	case ageDays < thresholdDays30:
		return "new_domain_30d", weightNewDomain30d
	case ageDays < thresholdDays90:
		return "new_domain_90d", weightNewDomain90d
	case ageDays < thresholdDays365:
		return "new_domain_365d", weightNewDomain365d
	default:
		return "", 0
	}
}
