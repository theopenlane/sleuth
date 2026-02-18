package scanner

import (
	"sort"
	"time"
)

const (
	// defaultDNSTimeout is the default timeout for DNS queries.
	defaultDNSTimeout = 10 * time.Second
	// defaultDNSRetries is the default number of DNS retry attempts.
	defaultDNSRetries = 2
	// defaultMaxSubdomains is the default cap on subdomain enumeration results.
	defaultMaxSubdomains = 100
	// defaultSubfinderThreads is the default thread count for subfinder.
	defaultSubfinderThreads = 10
	// defaultHTTPTimeout is the default timeout for HTTP probing.
	defaultHTTPTimeout = 10 * time.Second
	// defaultHTTPThreads is the default thread count for HTTP probing.
	defaultHTTPThreads = 25
	// defaultHTTPRetries is the default number of HTTP retry attempts.
	defaultHTTPRetries = 2
	// defaultNucleiTimeout is the default timeout for nuclei scans.
	defaultNucleiTimeout = 90 * time.Second
	// defaultMaxConcurrency is the default cap on concurrent operations.
	defaultMaxConcurrency = 50
	// defaultNucleiPath is the default nuclei executable path.
	defaultNucleiPath = "nuclei"
	// defaultMaxSubdomainTakeoverChecks is the upper bound on takeover checks per scan.
	defaultMaxSubdomainTakeoverChecks = 20
)

// ScanOptions configures scanner behavior.
type ScanOptions struct {
	// DNSTimeout is the timeout for DNS queries.
	DNSTimeout time.Duration
	// DNSResolvers is the list of DNS resolver addresses to use.
	DNSResolvers []string
	// DNSRetries is the number of DNS retry attempts.
	DNSRetries int
	// MaxSubdomains is the maximum number of subdomains to enumerate.
	MaxSubdomains int
	// SubfinderSources is the list of data sources for subfinder.
	SubfinderSources []string
	// SubfinderThreads is the thread count for subfinder operations.
	SubfinderThreads int
	// HTTPTimeout is the timeout for HTTP probing requests.
	HTTPTimeout time.Duration
	// HTTPThreads is the worker count for HTTP-heavy operations.
	HTTPThreads int
	// HTTPRetries is the number of HTTP retry attempts.
	HTTPRetries int
	// NucleiPath is the executable path for nuclei.
	NucleiPath string
	// NucleiTemplates is the list of nuclei template categories to scan with.
	NucleiTemplates []string
	// NucleiSeverity is the list of nuclei severity levels to include.
	NucleiSeverity []string
	// NucleiTimeout is the timeout for nuclei scan operations.
	NucleiTimeout time.Duration
	// Verbose enables verbose logging output.
	Verbose bool
	// Silent suppresses non-essential external tool output.
	Silent bool
	// MaxConcurrency is the cap on concurrent operations.
	MaxConcurrency int
	// MaxSubdomainTakeoverChecks bounds takeover checks for scalability.
	MaxSubdomainTakeoverChecks int
	// InterestingSubdomainPatterns are marker tokens used to classify discovered subdomains.
	InterestingSubdomainPatterns []string
	// InterestingSubdomainContexts maps marker tokens to their contextual label.
	InterestingSubdomainContexts map[string]string
}

// ScanOption is a functional option for configuring scanner.
type ScanOption func(*ScanOptions)

// DefaultScanOptions returns default scanner options.
func DefaultScanOptions() *ScanOptions {
	return &ScanOptions{
		DNSTimeout:                   defaultDNSTimeout,
		DNSResolvers:                 []string{"8.8.8.8", "1.1.1.1"},
		DNSRetries:                   defaultDNSRetries,
		MaxSubdomains:                defaultMaxSubdomains,
		SubfinderSources:             []string{"virustotal", "shodan", "crtsh"},
		SubfinderThreads:             defaultSubfinderThreads,
		HTTPTimeout:                  defaultHTTPTimeout,
		HTTPThreads:                  defaultHTTPThreads,
		HTTPRetries:                  defaultHTTPRetries,
		NucleiPath:                   defaultNucleiPath,
		NucleiTemplates:              []string{"cves", "exposed-panels", "technologies", "misconfiguration"},
		NucleiSeverity:               []string{"critical", "high", "medium"},
		NucleiTimeout:                defaultNucleiTimeout,
		Verbose:                      false,
		Silent:                       true,
		MaxConcurrency:               defaultMaxConcurrency,
		MaxSubdomainTakeoverChecks:   defaultMaxSubdomainTakeoverChecks,
		InterestingSubdomainPatterns: defaultInterestingSubdomainPatterns(),
		InterestingSubdomainContexts: cloneSubdomainContextMap(
			defaultInterestingSubdomainContexts,
		),
	}
}

func cloneStringSlice(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	cloned := make([]string, len(values))
	copy(cloned, values)

	return cloned
}

func cloneSubdomainContextMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}

	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}

	return cloned
}

// WithDNSTimeout sets DNS query timeout.
func WithDNSTimeout(timeout time.Duration) ScanOption {
	return func(o *ScanOptions) {
		if timeout > 0 {
			o.DNSTimeout = timeout
		}
	}
}

// WithDNSResolvers sets custom DNS resolvers.
func WithDNSResolvers(resolvers []string) ScanOption {
	return func(o *ScanOptions) {
		if len(resolvers) > 0 {
			o.DNSResolvers = cloneStringSlice(resolvers)
		}
	}
}

// WithMaxSubdomains sets maximum subdomains to discover.
func WithMaxSubdomains(limit int) ScanOption {
	return func(o *ScanOptions) {
		if limit > 0 {
			o.MaxSubdomains = limit
		}
	}
}

// WithSubfinderSources sets subfinder data sources.
func WithSubfinderSources(sources []string) ScanOption {
	return func(o *ScanOptions) {
		if len(sources) > 0 {
			o.SubfinderSources = cloneStringSlice(sources)
		}
	}
}

// WithSubfinderThreads sets subfinder worker count.
func WithSubfinderThreads(threads int) ScanOption {
	return func(o *ScanOptions) {
		if threads > 0 {
			o.SubfinderThreads = threads
		}
	}
}

// WithHTTPTimeout sets HTTP probe timeout.
func WithHTTPTimeout(timeout time.Duration) ScanOption {
	return func(o *ScanOptions) {
		if timeout > 0 {
			o.HTTPTimeout = timeout
		}
	}
}

// WithHTTPRetries sets HTTP retry count.
func WithHTTPRetries(retries int) ScanOption {
	return func(o *ScanOptions) {
		if retries >= 0 {
			o.HTTPRetries = retries
		}
	}
}

// WithHTTPThreads sets HTTP worker count.
func WithHTTPThreads(threads int) ScanOption {
	return func(o *ScanOptions) {
		if threads > 0 {
			o.HTTPThreads = threads
		}
	}
}

// WithNucleiPath sets the nuclei executable path.
func WithNucleiPath(path string) ScanOption {
	return func(o *ScanOptions) {
		if path != "" {
			o.NucleiPath = path
		}
	}
}

// WithNucleiTemplates sets nuclei template categories.
func WithNucleiTemplates(templates []string) ScanOption {
	return func(o *ScanOptions) {
		o.NucleiTemplates = cloneStringSlice(templates)
	}
}

// WithNucleiSeverity sets nuclei severity levels.
func WithNucleiSeverity(severity []string) ScanOption {
	return func(o *ScanOptions) {
		o.NucleiSeverity = cloneStringSlice(severity)
	}
}

// WithNucleiTimeout sets nuclei timeout.
func WithNucleiTimeout(timeout time.Duration) ScanOption {
	return func(o *ScanOptions) {
		if timeout > 0 {
			o.NucleiTimeout = timeout
		}
	}
}

// WithVerbose enables verbose logging.
func WithVerbose(verbose bool) ScanOption {
	return func(o *ScanOptions) {
		o.Verbose = verbose
		if verbose {
			o.Silent = false
		}
	}
}

// WithSilent controls silent mode.
func WithSilent(silent bool) ScanOption {
	return func(o *ScanOptions) {
		o.Silent = silent
		if silent {
			o.Verbose = false
		}
	}
}

// WithMaxConcurrency sets maximum concurrent operations.
func WithMaxConcurrency(limit int) ScanOption {
	return func(o *ScanOptions) {
		if limit > 0 {
			o.MaxConcurrency = limit
		}
	}
}

// WithMaxSubdomainTakeoverChecks sets takeover check cap.
func WithMaxSubdomainTakeoverChecks(limit int) ScanOption {
	return func(o *ScanOptions) {
		if limit > 0 {
			o.MaxSubdomainTakeoverChecks = limit
		}
	}
}

// WithInterestingSubdomainContexts overrides interesting subdomain context mapping.
func WithInterestingSubdomainContexts(contexts map[string]string) ScanOption {
	return func(o *ScanOptions) {
		if len(contexts) == 0 {
			return
		}

		o.InterestingSubdomainContexts = cloneSubdomainContextMap(contexts)
		patterns := make([]string, 0, len(contexts))
		for pattern := range contexts {
			patterns = append(patterns, pattern)
		}
		sort.Strings(patterns)
		o.InterestingSubdomainPatterns = patterns
	}
}
