package emailauth

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// startTestDNSServer launches a local DNS server that responds with preconfigured records
func startTestDNSServer(t *testing.T, handler dns.Handler) string {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	server := &dns.Server{
		PacketConn: pc,
		Handler:    handler,
	}

	go func() { _ = server.ActivateAndServe() }()

	t.Cleanup(func() { _ = server.Shutdown() })

	return pc.LocalAddr().String()
}

// testHandler routes queries to the appropriate response
type testHandler struct {
	spfRecord   string
	dmarcRecord string
	dkimRecords map[string]string // selector -> record
}

func (h *testHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	if len(r.Question) == 0 {
		_ = w.WriteMsg(msg)
		return
	}

	qname := r.Question[0].Name

	switch {
	case r.Question[0].Qtype == dns.TypeTXT && hasSuffix(qname, "_dmarc."):
		if h.dmarcRecord != "" {
			msg.Answer = append(msg.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
				Txt: []string{h.dmarcRecord},
			})
		}
	case r.Question[0].Qtype == dns.TypeTXT && hasSuffix(qname, "_domainkey."):
		for selector, record := range h.dkimRecords {
			expected := selector + "._domainkey."
			if hasPrefix(qname, expected) && record != "" {
				msg.Answer = append(msg.Answer, &dns.TXT{
					Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
					Txt: []string{record},
				})
			}
		}
	case r.Question[0].Qtype == dns.TypeTXT:
		if h.spfRecord != "" {
			msg.Answer = append(msg.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
				Txt: []string{h.spfRecord},
			})
		}
	}

	_ = w.WriteMsg(msg)
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func hasSuffix(s, suffix string) bool {
	// check if the suffix appears anywhere as a label boundary
	for i := range s {
		if len(s[i:]) >= len(suffix) && s[i:i+len(suffix)] == suffix {
			return true
		}
	}

	return false
}

func TestAnalyzer_SPFGrading(t *testing.T) {
	cases := []struct {
		name         string
		spfRecord    string
		wantCategory string
		wantGrade    string
	}{
		{
			name:         "missing SPF",
			spfRecord:    "",
			wantCategory: "missing_spf",
			wantGrade:    "C",
		},
		{
			name:         "pass all",
			spfRecord:    "v=spf1 +all",
			wantCategory: "weak_spf",
			wantGrade:    "C",
		},
		{
			name:         "neutral all",
			spfRecord:    "v=spf1 include:example.com ?all",
			wantCategory: "weak_spf",
			wantGrade:    "B",
		},
		{
			name:         "softfail",
			spfRecord:    "v=spf1 include:example.com ~all",
			wantCategory: "",
			wantGrade:    "A",
		},
		{
			name:         "hardfail",
			spfRecord:    "v=spf1 include:example.com -all",
			wantCategory: "",
			wantGrade:    "A",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Provide good DMARC and DKIM so only SPF varies
			handler := &testHandler{
				spfRecord:   tc.spfRecord,
				dmarcRecord: "v=DMARC1; p=reject",
				dkimRecords: map[string]string{"google": "v=DKIM1; p=MIGf"},
			}
			addr := startTestDNSServer(t, handler)

			analyzer := NewAnalyzer(WithDNSServer(addr), WithDNSTimeout(2*time.Second))
			ctx := context.Background()

			resultAny, matches, err := analyzer.Analyze(ctx, "example.com")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			result, ok := resultAny.(Result)
			if !ok {
				t.Fatal("expected Result type")
			}

			if tc.wantCategory == "" {
				for _, m := range matches {
					for _, cat := range m.Categories {
						if cat == "missing_spf" || cat == "weak_spf" {
							t.Fatalf("unexpected SPF match category: %s", cat)
						}
					}
				}
			} else {
				found := false
				for _, m := range matches {
					for _, cat := range m.Categories {
						if cat == tc.wantCategory {
							found = true
						}
					}
				}

				if !found {
					t.Fatalf("expected category %s in matches", tc.wantCategory)
				}
			}

			if result.Grade != tc.wantGrade {
				t.Fatalf("expected grade %s, got %s", tc.wantGrade, result.Grade)
			}
		})
	}
}

func TestAnalyzer_DMARCGrading(t *testing.T) {
	cases := []struct {
		name         string
		dmarcRecord  string
		wantCategory string
	}{
		{
			name:         "missing DMARC",
			dmarcRecord:  "",
			wantCategory: "missing_dmarc",
		},
		{
			name:         "policy none",
			dmarcRecord:  "v=DMARC1; p=none; rua=mailto:dmarc@example.com",
			wantCategory: "weak_dmarc",
		},
		{
			name:         "policy quarantine",
			dmarcRecord:  "v=DMARC1; p=quarantine;",
			wantCategory: "",
		},
		{
			name:         "policy reject",
			dmarcRecord:  "v=DMARC1; p=reject; pct=100",
			wantCategory: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// SPF hardfail so only DMARC contributes
			handler := &testHandler{
				spfRecord:   "v=spf1 -all",
				dmarcRecord: tc.dmarcRecord,
				dkimRecords: map[string]string{"google": "v=DKIM1; p=MIGf"},
			}
			addr := startTestDNSServer(t, handler)

			analyzer := NewAnalyzer(WithDNSServer(addr), WithDNSTimeout(2*time.Second))
			ctx := context.Background()

			_, matches, err := analyzer.Analyze(ctx, "example.com")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tc.wantCategory == "" {
				for _, m := range matches {
					for _, cat := range m.Categories {
						if cat == "missing_dmarc" || cat == "weak_dmarc" {
							t.Fatalf("unexpected DMARC match category: %s", cat)
						}
					}
				}
			} else {
				found := false
				for _, m := range matches {
					for _, cat := range m.Categories {
						if cat == tc.wantCategory {
							found = true
						}
					}
				}

				if !found {
					t.Fatalf("expected category %s in matches", tc.wantCategory)
				}
			}
		})
	}
}

func TestAnalyzer_DKIMProbing(t *testing.T) {
	cases := []struct {
		name         string
		dkimRecords  map[string]string
		wantCategory string
		wantFound    bool
	}{
		{
			name:         "no selectors found",
			dkimRecords:  nil,
			wantCategory: "missing_dkim",
			wantFound:    false,
		},
		{
			name:         "google selector found",
			dkimRecords:  map[string]string{"google": "v=DKIM1; p=MIGfMA0GCSqGSIb3"},
			wantCategory: "",
			wantFound:    true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handler := &testHandler{
				spfRecord:   "v=spf1 -all",
				dmarcRecord: "v=DMARC1; p=reject",
				dkimRecords: tc.dkimRecords,
			}
			addr := startTestDNSServer(t, handler)

			analyzer := NewAnalyzer(WithDNSServer(addr), WithDNSTimeout(2*time.Second))
			ctx := context.Background()

			resultAny, matches, err := analyzer.Analyze(ctx, "example.com")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			result, ok := resultAny.(Result)
			if !ok {
				t.Fatal("expected Result type")
			}

			if result.DKIM.Found != tc.wantFound {
				t.Fatalf("expected DKIM found=%v, got %v", tc.wantFound, result.DKIM.Found)
			}

			if tc.wantCategory == "" {
				for _, m := range matches {
					for _, cat := range m.Categories {
						if cat == "missing_dkim" {
							t.Fatalf("unexpected DKIM match category: %s", cat)
						}
					}
				}
			} else {
				found := false
				for _, m := range matches {
					for _, cat := range m.Categories {
						if cat == tc.wantCategory {
							found = true
						}
					}
				}

				if !found {
					t.Fatalf("expected category %s in matches", tc.wantCategory)
				}
			}
		})
	}
}

func TestAnalyzer_EmptyDomain(t *testing.T) {
	analyzer := NewAnalyzer()
	_, _, err := analyzer.Analyze(context.Background(), "")

	if err != ErrEmptyDomain {
		t.Fatalf("expected ErrEmptyDomain, got %v", err)
	}
}

func TestAnalyzer_FullPassGradeA(t *testing.T) {
	handler := &testHandler{
		spfRecord:   "v=spf1 include:_spf.google.com -all",
		dmarcRecord: "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100",
		dkimRecords: map[string]string{"google": "v=DKIM1; p=MIGfMA0GCSqGSIb3"},
	}
	addr := startTestDNSServer(t, handler)

	analyzer := NewAnalyzer(WithDNSServer(addr), WithDNSTimeout(2*time.Second))
	resultAny, matches, err := analyzer.Analyze(context.Background(), "example.com")

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result, ok := resultAny.(Result)
	if !ok {
		t.Fatal("expected Result type")
	}

	if len(matches) != 0 {
		t.Fatalf("expected 0 matches for fully configured domain, got %d", len(matches))
	}

	if result.Grade != "A" {
		t.Fatalf("expected grade A, got %s", result.Grade)
	}
}

func TestExtractAllMechanism(t *testing.T) {
	cases := []struct {
		record string
		want   string
	}{
		{"v=spf1 -all", "-all"},
		{"v=spf1 ~all", "~all"},
		{"v=spf1 +all", "+all"},
		{"v=spf1 ?all", "?all"},
		{"v=spf1 include:example.com", ""},
		{"v=spf1 all", "+all"},
	}

	for _, tc := range cases {
		got := extractAllMechanism(tc.record)
		if got != tc.want {
			t.Errorf("extractAllMechanism(%q) = %q, want %q", tc.record, got, tc.want)
		}
	}
}

func TestParseDMARC(t *testing.T) {
	cases := []struct {
		name      string
		record    string
		wantPolicy string
		wantPct   int
		wantRUA   string
	}{
		{
			name:      "full record",
			record:    "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=50",
			wantPolicy: "reject",
			wantPct:   50,
			wantRUA:   "mailto:dmarc@example.com",
		},
		{
			name:      "none policy",
			record:    "v=DMARC1; p=none;",
			wantPolicy: "none",
			wantPct:   defaultDMARCPct,
			wantRUA:   "",
		},
		{
			name:       "quarantine no pct",
			record:     "v=DMARC1; p=quarantine",
			wantPolicy: "quarantine",
			wantPct:    defaultDMARCPct,
			wantRUA:    "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := parseDMARC(tc.record)
			if result.Policy != tc.wantPolicy {
				t.Fatalf("expected policy %q, got %q", tc.wantPolicy, result.Policy)
			}

			if result.Percentage != tc.wantPct {
				t.Fatalf("expected pct %d, got %d", tc.wantPct, result.Percentage)
			}

			if result.ReportURI != tc.wantRUA {
				t.Fatalf("expected rua %q, got %q", tc.wantRUA, result.ReportURI)
			}
		})
	}
}

func TestCalculateGrade(t *testing.T) {
	cases := []struct {
		weight int
		want   string
	}{
		{0, "A"},
		{10, "B"},
		{15, "C"},
		{20, "C"},
		{25, "D"},
		{30, "D"},
		{35, "F"},
		{45, "F"},
	}

	for _, tc := range cases {
		got := calculateGrade(tc.weight)
		if got != tc.want {
			t.Errorf("calculateGrade(%d) = %q, want %q", tc.weight, got, tc.want)
		}
	}
}
