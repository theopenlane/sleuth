package emailauth

import (
	"context"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// SPFResult captures the outcome of an SPF record lookup
type SPFResult struct {
	// Record is the raw SPF TXT record, empty if not found
	Record string `json:"record,omitempty"`
	// Mechanism is the trailing all-mechanism (e.g. "-all", "~all")
	Mechanism string `json:"mechanism,omitempty"`
	// Found indicates whether an SPF record was discovered
	Found bool `json:"found"`
}

// lookupSPF queries TXT records for the domain and parses SPF policy
func lookupSPF(ctx context.Context, client *dns.Client, server, domain string) SPFResult {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), dns.TypeTXT)
	msg.RecursionDesired = true

	resp, _, err := client.ExchangeContext(ctx, msg, server)
	if err != nil || resp == nil {
		return SPFResult{}
	}

	for _, rr := range resp.Answer {
		txt, ok := rr.(*dns.TXT)
		if !ok {
			continue
		}

		record := strings.Join(txt.Txt, "")
		if !strings.HasPrefix(strings.ToLower(record), "v=spf1") {
			continue
		}

		return SPFResult{
			Record:    record,
			Mechanism: extractAllMechanism(record),
			Found:     true,
		}
	}

	return SPFResult{}
}

// extractAllMechanism finds the all-mechanism in an SPF record
func extractAllMechanism(record string) string {
	lower := strings.ToLower(record)
	fields := strings.Fields(lower)

	for _, field := range fields {
		trimmed := strings.TrimSpace(field)
		switch trimmed {
		case "+all", "-all", "~all", "?all":
			return trimmed
		case "all":
			return "+all" // bare "all" is equivalent to "+all"
		}
	}

	return ""
}

// gradeSPF returns a category and weight for the SPF result
func gradeSPF(result SPFResult) (string, int) {
	if !result.Found {
		return "missing_spf", weightMissingSPF
	}

	switch result.Mechanism {
	case "+all":
		return "weak_spf", weightWeakSPFPassAll
	case "?all":
		return "weak_spf", weightWeakSPFNeutral
	case "~all", "-all":
		return "", 0 // acceptable or best practice
	default:
		// no all-mechanism is unusual but not penalized as missing
		return "", 0
	}
}

// spfDescription returns a human-readable description of the SPF grade
func spfDescription(result SPFResult) string {
	if !result.Found {
		return "No SPF record configured"
	}

	switch result.Mechanism {
	case "+all":
		return fmt.Sprintf("SPF record uses +all (passes all senders): %s", result.Record)
	case "?all":
		return fmt.Sprintf("SPF record uses ?all (neutral): %s", result.Record)
	case "~all":
		return fmt.Sprintf("SPF record uses ~all (softfail): %s", result.Record)
	case "-all":
		return fmt.Sprintf("SPF record uses -all (hardfail): %s", result.Record)
	default:
		return fmt.Sprintf("SPF record found: %s", result.Record)
	}
}
