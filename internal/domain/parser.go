package domain

import (
	"fmt"
	"net/url"
	"strings"
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

	parts := strings.Split(input, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid domain format")
	}

	info := &Info{
		Domain: input,
		TLD:    parts[len(parts)-1],
	}

	// Handle common TLDs with SLDs (e.g., .co.uk, .com.au)
	if len(parts) >= 3 && isPublicSuffix(parts[len(parts)-2] + "." + parts[len(parts)-1]) {
		info.TLD = parts[len(parts)-2] + "." + parts[len(parts)-1]
		info.SLD = parts[len(parts)-3]
		if len(parts) > 3 {
			info.Subdomain = strings.Join(parts[:len(parts)-3], ".")
		}
	} else {
		info.SLD = parts[len(parts)-2]
		if len(parts) > 2 {
			info.Subdomain = strings.Join(parts[:len(parts)-2], ".")
		}
	}

	return info, nil
}

// isPublicSuffix checks if a domain suffix is a known public suffix
func isPublicSuffix(suffix string) bool {
	// Simplified list of common public suffixes
	publicSuffixes := map[string]bool{
		"co.uk":  true,
		"com.au": true,
		"co.nz":  true,
		"co.za":  true,
		"com.br": true,
		"co.in":  true,
		"net.au": true,
		"org.uk": true,
		"ac.uk":  true,
		"gov.uk": true,
	}
	return publicSuffixes[suffix]
}