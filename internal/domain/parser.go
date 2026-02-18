package domain

import (
	"net/url"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Info contains parsed domain information
type Info struct {
	// Domain is the full domain name
	Domain string `json:"domain"`
	// Subdomain is the subdomain part if present
	Subdomain string `json:"subdomain,omitempty"`
	// TLD is the top-level domain
	TLD string `json:"tld"`
	// SLD is the second-level domain
	SLD string `json:"sld"`
}

// expectedEmailParts is the number of parts expected when splitting an email address on "@"
const expectedEmailParts = 2

// Parse extracts domain information from an email or domain string
func Parse(input string) (*Info, error) {
	// Extract domain from email if @ is present
	if strings.Contains(input, "@") {
		parts := strings.Split(input, "@")
		if len(parts) != expectedEmailParts {
			return nil, ErrInvalidEmailFormat
		}
		input = parts[1]
	}

	// Clean up domain
	input = strings.ToLower(strings.TrimSpace(input))

	// Remove protocol if present
	if strings.Contains(input, "://") {
		u, err := url.Parse(input)
		if err != nil {
			return nil, ErrInvalidURLFormat
		}
		input = u.Host
	}

	// Remove port if present
	if idx := strings.LastIndex(input, ":"); idx != -1 {
		input = input[:idx]
	}

	// Basic validation
	if input == "" || !strings.Contains(input, ".") {
		return nil, ErrInvalidDomainFormat
	}

	etld1, err := publicsuffix.EffectiveTLDPlusOne(input)
	if err != nil {
		return nil, ErrInvalidDomainFormat
	}

	tld, _ := publicsuffix.PublicSuffix(input)
	sld := strings.TrimSuffix(etld1, "."+tld)
	subdomain := ""
	if etld1 != input {
		subdomain = strings.TrimSuffix(input, "."+etld1)
	}

	info := &Info{
		Domain:    input,
		Subdomain: subdomain,
		TLD:       tld,
		SLD:       sld,
	}

	return info, nil
}
