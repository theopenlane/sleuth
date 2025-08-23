package types

// CheckResult contains the result of a domain check
type CheckResult struct {
	CheckName string                 `json:"check_name" example:"dns_analysis" description:"Name of the security check performed"`
	Status    string                 `json:"status" example:"pass" description:"Overall status of the check (pass/fail/error)"`
	Findings  []Finding              `json:"findings,omitempty" description:"List of security findings discovered"`
	Metadata  map[string]interface{} `json:"metadata,omitempty" description:"Additional metadata about the check results"`
	Error     string                 `json:"error,omitempty" example:"DNS lookup failed" description:"Error message if check failed"`
}

// Finding represents a specific finding from a check
type Finding struct {
	Severity    string `json:"severity" example:"high" description:"Severity level (critical/high/medium/low/info)"`
	Type        string `json:"type" example:"cname_takeover" description:"Type of security finding"`
	Description string `json:"description" example:"Potential CNAME takeover vulnerability" description:"Human-readable description of the finding"`
	Details     string `json:"details,omitempty" example:"CNAME points to unclaimed service" description:"Additional technical details"`
}

// ScanResult contains all results from scanning a domain
type ScanResult struct {
	Domain      string         `json:"domain" example:"example.com" description:"The domain that was scanned"`
	ScannedAt   string         `json:"scanned_at" example:"1705316400" description:"Unix timestamp when scan was performed"`
	Results     []CheckResult  `json:"results" description:"Results from all security and technology checks"`
	DomainInfo  *DomainInfo    `json:"domain_info" description:"Parsed domain information"`
}

// DomainInfo contains parsed domain information
type DomainInfo struct {
	Domain    string `json:"domain" example:"sub.example.com" description:"Full domain name"`
	Subdomain string `json:"subdomain,omitempty" example:"sub" description:"Subdomain part if present"`
	TLD       string `json:"tld" example:"com" description:"Top-level domain"`
	SLD       string `json:"sld" example:"example" description:"Second-level domain"`
}