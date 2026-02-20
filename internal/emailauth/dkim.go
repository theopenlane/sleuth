package emailauth

import (
	"context"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// DKIMResult captures the outcome of DKIM selector probing
type DKIMResult struct {
	// SelectorsFound lists the selectors for which DKIM TXT records were discovered
	SelectorsFound []string `json:"selectors_found,omitempty"`
	// SelectorsChecked is the total number of selectors probed
	SelectorsChecked int `json:"selectors_checked"`
	// Found indicates whether at least one DKIM selector was discovered
	Found bool `json:"found"`
}

// commonSelectors are well-known DKIM selectors probed during analysis
var commonSelectors = []string{
	"google",
	"default",
	"selector1",
	"selector2",
	"k1",
	"mandrill",
	"dkim",
	"mail",
	"s1",
	"s2",
}

// probeDKIM queries TXT records for each common DKIM selector
func probeDKIM(ctx context.Context, client *dns.Client, server, domain string) DKIMResult {
	result := DKIMResult{
		SelectorsChecked: len(commonSelectors),
	}

	for _, selector := range commonSelectors {
		if ctx.Err() != nil {
			break
		}

		qname := fmt.Sprintf("%s._domainkey.%s", selector, domain)
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(qname), dns.TypeTXT)
		msg.RecursionDesired = true

		resp, _, err := client.ExchangeContext(ctx, msg, server)
		if err != nil || resp == nil {
			continue
		}

		for _, rr := range resp.Answer {
			txt, ok := rr.(*dns.TXT)
			if !ok {
				continue
			}

			record := strings.Join(txt.Txt, "")
			if strings.Contains(strings.ToLower(record), "v=dkim1") || strings.Contains(strings.ToLower(record), "p=") {
				result.SelectorsFound = append(result.SelectorsFound, selector)
				result.Found = true

				break
			}
		}
	}

	return result
}

// gradeDKIM returns a category and weight for the DKIM result
func gradeDKIM(result DKIMResult) (string, int) {
	if !result.Found {
		return "missing_dkim", weightMissingDKIM
	}

	return "", 0
}
