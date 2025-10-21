package domain

import (
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Info contains parsed domain information
type Info struct {
	Domain    string `json:"domain"`
	Subdomain string `json:"subdomain,omitempty"`
	TLD       string `json:"tld"`
	SLD       string `json:"sld"`
}

// Parse extracts domain information from an email or domain string
func Parse(input string) (*Info, error) {
	// Extract domain from email if @ is present
	if strings.Contains(input, "@") {
		parts := strings.Split(input, "@")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid email format")
		}
		input = parts[1]
	}

	// Clean up domain
	input = strings.ToLower(strings.TrimSpace(input))

	// Remove protocol if present
	if strings.Contains(input, "://") {
		u, err := url.Parse(input)
		if err != nil {
			return nil, fmt.Errorf("invalid URL format: %w", err)
		}
		input = u.Host
	}

	// Remove port if present
	if idx := strings.LastIndex(input, ":"); idx != -1 {
		input = input[:idx]
	}

	// Basic validation
	if input == "" || !strings.Contains(input, ".") {
		return nil, fmt.Errorf("invalid domain format")
	}

	etld1, err := publicsuffix.EffectiveTLDPlusOne(input)
	if err != nil {
		return nil, fmt.Errorf("invalid domain format: %w", err)
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
