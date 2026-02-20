package emailauth

import (
	"context"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// DMARCResult captures the outcome of a DMARC record lookup
type DMARCResult struct {
	// Record is the raw DMARC TXT record, empty if not found
	Record string `json:"record,omitempty"`
	// Policy is the parsed p= value (none, quarantine, reject)
	Policy string `json:"policy,omitempty"`
	// ReportURI is the rua= value, if present
	ReportURI string `json:"report_uri,omitempty"`
	// Percentage is the pct= value, defaults to 100
	Percentage int `json:"percentage"`
	// Found indicates whether a DMARC record was discovered
	Found bool `json:"found"`
}

const (
	dmarcPrefix     = "_dmarc."
	defaultDMARCPct = 100
	// dmarcKVParts is the expected number of parts when splitting key=value pairs
	dmarcKVParts = 2
)

// lookupDMARC queries TXT records at _dmarc.<domain> and parses the policy
func lookupDMARC(ctx context.Context, client *dns.Client, server, domain string) DMARCResult {
	qname := dmarcPrefix + domain
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(qname), dns.TypeTXT)
	msg.RecursionDesired = true

	resp, _, err := client.ExchangeContext(ctx, msg, server)
	if err != nil || resp == nil {
		return DMARCResult{Percentage: defaultDMARCPct}
	}

	for _, rr := range resp.Answer {
		txt, ok := rr.(*dns.TXT)
		if !ok {
			continue
		}

		record := strings.Join(txt.Txt, "")
		if !strings.HasPrefix(strings.ToLower(record), "v=dmarc1") {
			continue
		}

		return parseDMARC(record)
	}

	return DMARCResult{Percentage: defaultDMARCPct}
}

// parseDMARC extracts policy fields from a DMARC record string
func parseDMARC(record string) DMARCResult {
	result := DMARCResult{
		Record:     record,
		Found:      true,
		Percentage: defaultDMARCPct,
	}

	parts := strings.Split(record, ";")
	for _, part := range parts {
		kv := strings.SplitN(strings.TrimSpace(part), "=", dmarcKVParts)
		if len(kv) != dmarcKVParts {
			continue
		}

		key := strings.TrimSpace(strings.ToLower(kv[0]))
		val := strings.TrimSpace(kv[1])

		switch key {
		case "p":
			result.Policy = strings.ToLower(val)
		case "rua":
			result.ReportURI = val
		case "pct":
			pct := parsePct(val)
			if pct >= 0 {
				result.Percentage = pct
			}
		}
	}

	return result
}

// parsePct attempts to parse a pct value as an integer in [0, 100]
func parsePct(val string) int {
	var pct int

	n, err := fmt.Sscanf(val, "%d", &pct)
	if err != nil || n != 1 {
		return -1
	}

	if pct < 0 || pct > defaultDMARCPct {
		return -1
	}

	return pct
}

// gradeDMARC returns a category and weight for the DMARC result
func gradeDMARC(result DMARCResult) (string, int) {
	if !result.Found {
		return "missing_dmarc", weightMissingDMARC
	}

	switch result.Policy {
	case "none":
		return "weak_dmarc", weightWeakDMARC
	case "quarantine", "reject":
		return "", 0 // acceptable or best practice
	default:
		return "", 0
	}
}

// dmarcDescription returns a human-readable description of the DMARC grade
func dmarcDescription(result DMARCResult) string {
	if !result.Found {
		return "No DMARC record configured"
	}

	switch result.Policy {
	case "none":
		return fmt.Sprintf("DMARC policy set to none (monitoring only): %s", result.Record)
	case "quarantine":
		return fmt.Sprintf("DMARC policy set to quarantine: %s", result.Record)
	case "reject":
		return fmt.Sprintf("DMARC policy set to reject: %s", result.Record)
	default:
		return fmt.Sprintf("DMARC record found: %s", result.Record)
	}
}
