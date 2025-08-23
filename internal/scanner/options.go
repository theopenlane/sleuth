package scanner

import (
	"time"
)

// ScanOptions configures the scanner behavior
type ScanOptions struct {
	// DNS options
	DNSTimeout       time.Duration
	DNSResolvers     []string
	DNSRetries       int
	
	// Subdomain discovery options
	MaxSubdomains    int
	SubfinderSources []string
	SubfinderThreads int
	
	// HTTP probing options
	HTTPTimeout      time.Duration
	HTTPThreads      int
	HTTPRetries      int
	
	// Nuclei options
	NucleiTemplates  []string
	NucleiSeverity   []string
	NucleiTimeout    time.Duration
	
	// General options
	Verbose          bool
	Silent           bool
	MaxConcurrency   int
}

// ScanOption is a functional option for configuring scanner
type ScanOption func(*ScanOptions)

// DefaultScanOptions returns default scanner options
func DefaultScanOptions() *ScanOptions {
	return &ScanOptions{
		DNSTimeout:       10 * time.Second,
		DNSResolvers:     []string{"8.8.8.8", "1.1.1.1"},
		DNSRetries:       2,
		MaxSubdomains:    100,
		SubfinderSources: []string{"virustotal", "shodan", "crtsh"},
		SubfinderThreads: 10,
		HTTPTimeout:      10 * time.Second,
		HTTPThreads:      25,
		HTTPRetries:      2,
		NucleiTemplates:  []string{"cves", "exposed-panels", "technologies", "misconfiguration"},
		NucleiSeverity:   []string{"critical", "high", "medium"},
		NucleiTimeout:    30 * time.Second,
		Verbose:          false,
		Silent:           true,
		MaxConcurrency:   50,
	}
}

// WithDNSTimeout sets DNS query timeout
func WithDNSTimeout(timeout time.Duration) ScanOption {
	return func(o *ScanOptions) {
		o.DNSTimeout = timeout
	}
}

// WithDNSResolvers sets custom DNS resolvers
func WithDNSResolvers(resolvers []string) ScanOption {
	return func(o *ScanOptions) {
		o.DNSResolvers = resolvers
	}
}

// WithMaxSubdomains sets maximum subdomains to discover
func WithMaxSubdomains(max int) ScanOption {
	return func(o *ScanOptions) {
		o.MaxSubdomains = max
	}
}

// WithSubfinderSources sets subfinder data sources
func WithSubfinderSources(sources []string) ScanOption {
	return func(o *ScanOptions) {
		o.SubfinderSources = sources
	}
}

// WithHTTPTimeout sets HTTP probe timeout
func WithHTTPTimeout(timeout time.Duration) ScanOption {
	return func(o *ScanOptions) {
		o.HTTPTimeout = timeout
	}
}

// WithNucleiTemplates sets nuclei template categories
func WithNucleiTemplates(templates []string) ScanOption {
	return func(o *ScanOptions) {
		o.NucleiTemplates = templates
	}
}

// WithNucleiSeverity sets nuclei severity levels
func WithNucleiSeverity(severity []string) ScanOption {
	return func(o *ScanOptions) {
		o.NucleiSeverity = severity
	}
}

// WithVerbose enables verbose logging
func WithVerbose(verbose bool) ScanOption {
	return func(o *ScanOptions) {
		o.Verbose = verbose
	}
}

// WithMaxConcurrency sets maximum concurrent operations
func WithMaxConcurrency(max int) ScanOption {
	return func(o *ScanOptions) {
		o.MaxConcurrency = max
	}
}