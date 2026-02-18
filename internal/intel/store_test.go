package intel

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestNewIndicatorStore(t *testing.T) {
	store := newIndicatorStore()
	if store == nil {
		t.Fatal("expected non-nil store")
	}
	if store.ip == nil {
		t.Error("expected ip map to be initialized")
	}
	if store.domain == nil {
		t.Error("expected domain map to be initialized")
	}
	if store.email == nil {
		t.Error("expected email map to be initialized")
	}
	if store.total != 0 {
		t.Errorf("expected total to be 0, got %d", store.total)
	}
}

func TestAddIndicator(t *testing.T) {
	feed := Feed{
		Name: "test_feed",
		Type: []string{"suspicious"},
	}

	testCases := []struct {
		name       string
		value      string
		typ        IndicatorType
		shouldAdd  bool
		checkTotal int
	}{
		{
			name:       "valid ip",
			value:      "203.0.113.10",
			typ:        IndicatorTypeIP,
			shouldAdd:  true,
			checkTotal: 1,
		},
		{
			name:       "valid domain",
			value:      "malicious.example.com",
			typ:        IndicatorTypeDomain,
			shouldAdd:  true,
			checkTotal: 2,
		},
		{
			name:       "valid email",
			value:      "spam@example.com",
			typ:        IndicatorTypeEmail,
			shouldAdd:  true,
			checkTotal: 3,
		},
		{
			name:       "valid cidr",
			value:      "198.51.100.0/24",
			typ:        IndicatorTypeCIDR,
			shouldAdd:  true,
			checkTotal: 4,
		},
		{
			name:       "empty value",
			value:      "",
			typ:        IndicatorTypeIP,
			shouldAdd:  false,
			checkTotal: 4,
		},
		{
			name:       "invalid cidr",
			value:      "invalid/cidr",
			typ:        IndicatorTypeCIDR,
			shouldAdd:  false,
			checkTotal: 4,
		},
	}

	store := newIndicatorStore()
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			added := store.addIndicator(tc.value, tc.typ, feed)
			if added != tc.shouldAdd {
				t.Errorf("expected added=%v, got %v", tc.shouldAdd, added)
			}
			if store.total != tc.checkTotal {
				t.Errorf("expected total=%d, got %d", tc.checkTotal, store.total)
			}
		})
	}
}

func TestAddIndicatorWithTypeFiltering(t *testing.T) {
	feedDomainOnly := Feed{
		Name:       "domain_only_feed",
		Type:       []string{"phishing"},
		Indicators: []IndicatorType{IndicatorTypeDomain},
	}

	store := newIndicatorStore()

	// Should accept domain
	if !store.addIndicator("bad.example.com", IndicatorTypeDomain, feedDomainOnly) {
		t.Error("expected domain to be added to domain-only feed")
	}

	// Should reject IP
	if store.addIndicator("203.0.113.10", IndicatorTypeIP, feedDomainOnly) {
		t.Error("expected IP to be rejected from domain-only feed")
	}

	// Should reject email
	if store.addIndicator("spam@example.com", IndicatorTypeEmail, feedDomainOnly) {
		t.Error("expected email to be rejected from domain-only feed")
	}

	if store.total != 1 {
		t.Errorf("expected total=1, got %d", store.total)
	}
}

func TestMatchIP(t *testing.T) {
	feed := Feed{
		Name: "test_feed",
		Type: []string{"suspicious", "c2"},
	}

	store := newIndicatorStore()
	store.addIndicator("203.0.113.10", IndicatorTypeIP, feed)
	store.addIndicator("198.51.100.0/24", IndicatorTypeCIDR, feed)

	testCases := []struct {
		name          string
		ip            string
		expectMatches int
	}{
		{
			name:          "exact ip match",
			ip:            "203.0.113.10",
			expectMatches: 1,
		},
		{
			name:          "cidr match",
			ip:            "198.51.100.50",
			expectMatches: 1,
		},
		{
			name:          "no match",
			ip:            "8.8.8.8",
			expectMatches: 0,
		},
		{
			name:          "nil ip",
			ip:            "",
			expectMatches: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var ip net.IP
			if tc.ip != "" {
				ip = net.ParseIP(tc.ip)
			}
			matches := store.matchIP(ip)
			if len(matches) != tc.expectMatches {
				t.Errorf("expected %d matches, got %d", tc.expectMatches, len(matches))
			}
			if len(matches) > 0 {
				if len(matches[0].Categories) == 0 {
					t.Error("expected categories in match")
				}
				if len(matches[0].Feeds) == 0 {
					t.Error("expected feeds in match")
				}
			}
		})
	}
}

func TestMatchDomain(t *testing.T) {
	feed := Feed{
		Name: "test_feed",
		Type: []string{"phishing"},
	}

	store := newIndicatorStore()
	store.addIndicator("malicious.example.com", IndicatorTypeDomain, feed)
	store.addIndicator("EVIL.EXAMPLE.COM", IndicatorTypeDomain, feed)

	testCases := []struct {
		name          string
		domain        string
		expectMatches int
	}{
		{
			name:          "exact match",
			domain:        "malicious.example.com",
			expectMatches: 1,
		},
		{
			name:          "case insensitive match",
			domain:        "MALICIOUS.EXAMPLE.COM",
			expectMatches: 1,
		},
		{
			name:          "another match",
			domain:        "evil.example.com",
			expectMatches: 1,
		},
		{
			name:          "no match",
			domain:        "safe.example.com",
			expectMatches: 0,
		},
		{
			name:          "empty domain",
			domain:        "",
			expectMatches: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			matches := store.matchDomain(tc.domain)
			if len(matches) != tc.expectMatches {
				t.Errorf("expected %d matches, got %d", tc.expectMatches, len(matches))
			}
		})
	}
}

func TestMatchEmail(t *testing.T) {
	feed := Feed{
		Name: "test_feed",
		Type: []string{"spam"},
	}

	store := newIndicatorStore()
	store.addIndicator("spam@example.com", IndicatorTypeEmail, feed)
	store.addIndicator("PHISHING@EXAMPLE.NET", IndicatorTypeEmail, feed)

	testCases := []struct {
		name          string
		email         string
		expectMatches int
	}{
		{
			name:          "exact match",
			email:         "spam@example.com",
			expectMatches: 1,
		},
		{
			name:          "case insensitive match",
			email:         "SPAM@EXAMPLE.COM",
			expectMatches: 1,
		},
		{
			name:          "another match",
			email:         "phishing@example.net",
			expectMatches: 1,
		},
		{
			name:          "no match",
			email:         "legitimate@example.com",
			expectMatches: 0,
		},
		{
			name:          "empty email",
			email:         "",
			expectMatches: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			matches := store.matchEmail(tc.email)
			if len(matches) != tc.expectMatches {
				t.Errorf("expected %d matches, got %d", tc.expectMatches, len(matches))
			}
		})
	}
}

func TestIngestFile(t *testing.T) {
	feed := Feed{
		Name: "test_feed",
		Type: []string{"suspicious"},
	}

	tmpDir := t.TempDir()
	feedFile := filepath.Join(tmpDir, "test_feed.txt")

	feedData := `# Comment line
203.0.113.10
198.51.100.0/24
malicious.example.com
spam@example.com

# Another comment
8.8.8.8
`

	if err := os.WriteFile(feedFile, []byte(feedData), 0o600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	store := newIndicatorStore()
	added, err := store.ingestFile(feedFile, feed)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if added != 5 {
		t.Errorf("expected 5 indicators added, got %d", added)
	}

	// Verify indicators were added correctly
	if len(store.matchIP(net.ParseIP("203.0.113.10"))) == 0 {
		t.Error("expected IP to be in store")
	}
	if len(store.matchIP(net.ParseIP("198.51.100.50"))) == 0 {
		t.Error("expected CIDR match to work")
	}
	if len(store.matchDomain("malicious.example.com")) == 0 {
		t.Error("expected domain to be in store")
	}
	if len(store.matchEmail("spam@example.com")) == 0 {
		t.Error("expected email to be in store")
	}
}

func TestIngestFileWithTypeFilter(t *testing.T) {
	feed := Feed{
		Name:       "domain_only",
		Type:       []string{"phishing"},
		Indicators: []IndicatorType{IndicatorTypeDomain},
	}

	tmpDir := t.TempDir()
	feedFile := filepath.Join(tmpDir, "mixed_feed.txt")

	feedData := `203.0.113.10
malicious.example.com
spam@example.com
198.51.100.0/24
`

	if err := os.WriteFile(feedFile, []byte(feedData), 0o600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	store := newIndicatorStore()
	added, err := store.ingestFile(feedFile, feed)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should only add domain, not IP/email/CIDR
	if added != 1 {
		t.Errorf("expected 1 indicator added (domain only), got %d", added)
	}

	if len(store.matchDomain("malicious.example.com")) == 0 {
		t.Error("expected domain to be in store")
	}
	if len(store.matchIP(net.ParseIP("203.0.113.10"))) != 0 {
		t.Error("expected IP to be filtered out")
	}
	if len(store.matchEmail("spam@example.com")) != 0 {
		t.Error("expected email to be filtered out")
	}
}

func TestIngestFileNonExistent(t *testing.T) {
	feed := Feed{
		Name: "test_feed",
		Type: []string{"suspicious"},
	}

	store := newIndicatorStore()
	_, err := store.ingestFile("/nonexistent/file.txt", feed)
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestRecordToMatch(t *testing.T) {
	rec := &indicatorRecord{
		value: "example.com",
		typ:   IndicatorTypeDomain,
		categories: map[string]struct{}{
			"phishing":   {},
			"suspicious": {},
		},
		feeds: map[string]struct{}{
			"feed1": {},
			"feed2": {},
		},
	}

	match := recordToMatch(rec)

	if match.Value != "example.com" {
		t.Errorf("expected value 'example.com', got %q", match.Value)
	}
	if match.Type != IndicatorTypeDomain {
		t.Errorf("expected type domain, got %q", match.Type)
	}
	if len(match.Categories) != 2 {
		t.Errorf("expected 2 categories, got %d", len(match.Categories))
	}
	if len(match.Feeds) != 2 {
		t.Errorf("expected 2 feeds, got %d", len(match.Feeds))
	}
}

func TestMultipleFeedsForSameIndicator(t *testing.T) {
	feed1 := Feed{
		Name: "feed1",
		Type: []string{"suspicious"},
	}
	feed2 := Feed{
		Name: "feed2",
		Type: []string{"c2", "bot"},
	}

	store := newIndicatorStore()
	store.addIndicator("203.0.113.10", IndicatorTypeIP, feed1)
	store.addIndicator("203.0.113.10", IndicatorTypeIP, feed2)

	matches := store.matchIP(net.ParseIP("203.0.113.10"))
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}

	// Should have categories from both feeds
	match := matches[0]
	if len(match.Categories) < 2 {
		t.Errorf("expected at least 2 categories (from both feeds), got %d", len(match.Categories))
	}

	// Should list both feeds
	if len(match.Feeds) != 2 {
		t.Errorf("expected 2 feeds, got %d", len(match.Feeds))
	}
}
