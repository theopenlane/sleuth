package types

// CheckStatus represents the normalized lifecycle status of a check.
type CheckStatus string

const (
	// CheckStatusPass indicates the check completed and found no failing issues.
	CheckStatusPass CheckStatus = "pass"
	// CheckStatusFail indicates the check completed and found one or more failing issues.
	CheckStatusFail CheckStatus = "fail"
	// CheckStatusError indicates the check could not complete due to an execution error.
	CheckStatusError CheckStatus = "error"
	// CheckStatusSkipped indicates the check was intentionally skipped.
	CheckStatusSkipped CheckStatus = "skipped"
	// CheckStatusTimeout indicates the check timed out before completion.
	CheckStatusTimeout CheckStatus = "timeout"
)

// CheckResult contains the result of a domain check
type CheckResult struct {
	// CheckName is the name of the security check performed
	CheckName string `json:"check_name" example:"dns_analysis" description:"Name of the security check performed"`
	// Status is the normalized outcome of the check (pass/fail/error/skipped/timeout)
	Status CheckStatus `json:"status" example:"pass" description:"Normalized check status (pass/fail/error/skipped/timeout)"`
	// Findings holds the list of security findings discovered
	Findings []Finding `json:"findings,omitempty" description:"List of security findings discovered"`
	// Metadata holds additional metadata about the check results
	Metadata map[string]any `json:"metadata,omitempty" description:"Additional metadata about the check results"`
	// Error is the error message if the check failed
	Error string `json:"error,omitempty" example:"DNS lookup failed" description:"Error message if check failed"`
}

// Finding represents a specific finding from a check
type Finding struct {
	// Severity is the severity level of the finding (critical/high/medium/low/info)
	Severity string `json:"severity" example:"high" description:"Severity level (critical/high/medium/low/info)"`
	// Type is the category of security finding
	Type string `json:"type" example:"cname_takeover" description:"Type of security finding"`
	// Description is a human-readable description of the finding
	Description string `json:"description" example:"Potential CNAME takeover vulnerability" description:"Human-readable description of the finding"`
	// Details holds additional technical details about the finding
	Details string `json:"details,omitempty" example:"CNAME points to unclaimed service" description:"Additional technical details"`
}

// ScanResult contains all results from scanning a domain
type ScanResult struct {
	// Domain is the domain that was scanned
	Domain string `json:"domain" example:"example.com" description:"The domain that was scanned"`
	// Email is the email address if one was provided
	Email string `json:"email,omitempty" example:"user@example.com" description:"Email address if provided"`
	// ScannedAt is the unix timestamp when the scan was performed
	ScannedAt string `json:"scanned_at" example:"1705316400" description:"Unix timestamp when scan was performed"`
	// Results holds the results from all security and technology checks
	Results []CheckResult `json:"results" description:"Results from all security and technology checks"`
	// DomainInfo holds the parsed domain information
	DomainInfo *DomainInfo `json:"domain_info,omitempty" description:"Parsed domain information"`
	// IntelScore holds the threat intelligence score if an email was checked
	IntelScore any `json:"intel_score,omitempty" description:"Threat intelligence score if email was checked"`
}

// DomainInfo contains parsed domain information
type DomainInfo struct {
	// Domain is the full domain name
	Domain string `json:"domain" example:"sub.example.com" description:"Full domain name"`
	// Subdomain is the subdomain part if present
	Subdomain string `json:"subdomain,omitempty" example:"sub" description:"Subdomain part if present"`
	// TLD is the top-level domain
	TLD string `json:"tld" example:"com" description:"Top-level domain"`
	// SLD is the second-level domain
	SLD string `json:"sld" example:"example" description:"Second-level domain"`
}
