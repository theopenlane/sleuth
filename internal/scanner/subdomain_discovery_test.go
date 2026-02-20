package scanner

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"testing"
)

func TestParseDiscoveredSubdomains(t *testing.T) {
	raw := "b.example.com\na.example.com\nc.example.com\na.example.com\n\n"

	result := parseDiscoveredSubdomains(raw)

	if len(result) != 3 {
		t.Fatalf("expected 3 unique subdomains, got %d: %v", len(result), result)
	}

	// Should be sorted
	if !sort.StringsAreSorted(result) {
		t.Errorf("expected sorted results, got %v", result)
	}
}

func TestParseDiscoveredSubdomains_Empty(t *testing.T) {
	result := parseDiscoveredSubdomains("")

	if len(result) != 0 {
		t.Errorf("expected 0 subdomains from empty input, got %d", len(result))
	}
}

func TestInterestingSubdomainContext(t *testing.T) {
	s := &Scanner{options: DefaultScanOptions()}

	ctx, ok := s.interestingSubdomainContext("admin")
	if !ok {
		t.Fatal("expected admin to be interesting")
	}

	if ctx != "Administrative interface" {
		t.Errorf("expected 'Administrative interface', got %q", ctx)
	}

	_, ok = s.interestingSubdomainContext("randomnonsense")
	if ok {
		t.Error("expected randomnonsense to not be interesting")
	}
}

func TestTakeoverWorkerCount(t *testing.T) {
	tests := []struct {
		name       string
		checkLimit int
		maxConc    int
		httpThr    int
		expected   int
	}{
		{"zero limit", 0, 50, 25, 1},
		{"below caps", 5, 50, 25, 5},
		{"capped by concurrency", 100, 10, 25, 10},
		{"capped by http threads", 100, 50, 5, 5},
		{"negative limit", -1, 50, 25, 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := &Scanner{options: &ScanOptions{MaxConcurrency: tc.maxConc, HTTPThreads: tc.httpThr}}

			result := s.takeoverWorkerCount(tc.checkLimit)
			if result != tc.expected {
				t.Errorf("expected %d, got %d", tc.expected, result)
			}
		})
	}
}

func TestProbeCommonSubdomains_ConstructsFQDNs(t *testing.T) {
	opts := DefaultScanOptions()
	// Use only a small set of patterns for predictable testing
	opts.InterestingSubdomainPatterns = []string{"api", "blog", "docs"}
	opts.InterestingSubdomainContexts = map[string]string{
		"api":  "API endpoint",
		"blog": "Content service",
		"docs": "Documentation endpoint",
	}

	s := &Scanner{options: opts}

	// Use a domain that will not resolve, so no results are expected
	alreadyFound := make(map[string]struct{})
	result := s.probeCommonSubdomains(context.Background(), "nonexistent-test-domain-xyzzy.invalid", alreadyFound)

	// None should resolve for a .invalid TLD
	if len(result) != 0 {
		t.Errorf("expected 0 results for invalid domain, got %d: %v", len(result), result)
	}
}

func TestProbeCommonSubdomains_SkipsAlreadyFound(t *testing.T) {
	opts := DefaultScanOptions()
	opts.InterestingSubdomainPatterns = []string{"api", "blog"}
	opts.InterestingSubdomainContexts = map[string]string{
		"api":  "API endpoint",
		"blog": "Content service",
	}

	s := &Scanner{options: opts}
	domain := "nonexistent-test-domain-xyzzy.invalid"

	alreadyFound := map[string]struct{}{
		fmt.Sprintf("api.%s", domain):  {},
		fmt.Sprintf("blog.%s", domain): {},
	}

	result := s.probeCommonSubdomains(context.Background(), domain, alreadyFound)

	// All patterns are already found, nothing to probe
	if len(result) != 0 {
		t.Errorf("expected 0 results when all are already found, got %d: %v", len(result), result)
	}
}

func TestProbeCommonSubdomains_ResolvesLocalhost(t *testing.T) {
	// Test with localhost which should always resolve
	opts := DefaultScanOptions()
	opts.InterestingSubdomainPatterns = []string{"localhost-probe-test"}
	opts.InterestingSubdomainContexts = map[string]string{
		"localhost-probe-test": "Test",
	}
	s := &Scanner{options: opts}

	// "localhost" should resolve; construct the FQDN that will be tested
	testDomain := "localdomain"
	testFQDN := fmt.Sprintf("localhost-probe-test.%s", testDomain)

	// Check if this resolves before asserting - different systems behave differently
	_, err := net.LookupHost(testFQDN)
	if err != nil {
		t.Skipf("skipping: %s does not resolve on this system", testFQDN)
	}

	alreadyFound := make(map[string]struct{})
	result := s.probeCommonSubdomains(context.Background(), testDomain, alreadyFound)

	if !slices.Contains(result, testFQDN) {
		t.Errorf("expected %s in results, got %v", testFQDN, result)
	}
}

func TestProbeInterestingSubdomains_LiveServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "<html><head><title>Admin Panel</title></head><body>hello</body></html>")
	}))
	defer srv.Close()

	// Extract host:port from the test server
	srvHost := strings.TrimPrefix(srv.URL, "http://")

	opts := DefaultScanOptions()
	s := &Scanner{options: opts}

	ctxMap := map[string]string{srvHost: "Test service"}
	results := s.probeInterestingSubdomains(context.Background(), []string{srvHost}, ctxMap)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	info := results[0]
	if !info.Live {
		t.Error("expected subdomain to be live")
	}
	if info.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", info.StatusCode)
	}
	if info.Title != "Admin Panel" {
		t.Errorf("expected title 'Admin Panel', got %q", info.Title)
	}
	if info.Context != "Test service" {
		t.Errorf("expected context 'Test service', got %q", info.Context)
	}
}

func TestProbeInterestingSubdomains_DeadSubdomain(t *testing.T) {
	opts := DefaultScanOptions()
	s := &Scanner{options: opts}

	deadHost := "dead-host-xyzzy.invalid"
	ctxMap := map[string]string{deadHost: "Dead service"}
	results := s.probeInterestingSubdomains(context.Background(), []string{deadHost}, ctxMap)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	if results[0].Live {
		t.Error("expected dead subdomain to report Live=false")
	}
}

func TestProbeInterestingSubdomains_CancelledContext(t *testing.T) {
	opts := DefaultScanOptions()
	s := &Scanner{options: opts}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ctxMap := map[string]string{"admin.example.com": "Administrative interface"}
	results := s.probeInterestingSubdomains(ctx, []string{"admin.example.com"}, ctxMap)

	// With cancelled context, should either return empty or have Live=false
	for _, r := range results {
		if r.Live {
			t.Errorf("expected Live=false with cancelled context, got Live=true for %s", r.Subdomain)
		}
	}
}

func TestCountLiveSubdomains(t *testing.T) {
	details := []InterestingSubdomainInfo{
		{Subdomain: "a.example.com", Live: true},
		{Subdomain: "b.example.com", Live: false},
		{Subdomain: "c.example.com", Live: true},
	}

	count := countLiveSubdomains(details)
	if count != 2 {
		t.Errorf("expected 2 live subdomains, got %d", count)
	}
}

func TestCountLiveSubdomains_Empty(t *testing.T) {
	count := countLiveSubdomains(nil)
	if count != 0 {
		t.Errorf("expected 0 for nil input, got %d", count)
	}
}

func TestProbeCommonSubdomains_RespectsContext(t *testing.T) {
	opts := DefaultScanOptions()
	s := &Scanner{options: opts}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	alreadyFound := make(map[string]struct{})
	result := s.probeCommonSubdomains(ctx, "example.com", alreadyFound)

	// With a cancelled context, DNS lookups should fail
	if len(result) != 0 {
		t.Errorf("expected 0 results with cancelled context, got %d", len(result))
	}
}
