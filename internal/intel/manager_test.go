package intel

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestParseIndicator(t *testing.T) {
	t.Helper()

	cases := []struct {
		name  string
		line  string
		value string
		typ   IndicatorType
	}{
		{
			name:  "ipv4",
			line:  "203.0.113.10",
			value: "203.0.113.10",
			typ:   IndicatorTypeIP,
		},
		{
			name:  "ipv6",
			line:  "2001:db8::1",
			value: "2001:db8::1",
			typ:   IndicatorTypeIP,
		},
		{
			name:  "cidr",
			line:  "198.51.100.0/24",
			value: "198.51.100.0/24",
			typ:   IndicatorTypeCIDR,
		},
		{
			name:  "domain",
			line:  "bad.example.com,additional,data",
			value: "bad.example.com",
			typ:   IndicatorTypeDomain,
		},
		{
			name:  "email",
			line:  "malicious@example.net # comment",
			value: "malicious@example.net",
			typ:   IndicatorTypeEmail,
		},
		{
			name:  "ignore private",
			line:  "10.0.0.1",
			value: "",
			typ:   "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			val, typ := parseIndicator(tc.line)
			if val != tc.value {
				t.Fatalf("expected value %q, got %q", tc.value, val)
			}
			if typ != tc.typ {
				t.Fatalf("expected type %q, got %q", tc.typ, typ)
			}
		})
	}
}

func TestManagerHydrateAndCheck(t *testing.T) {
	feedData := "203.0.113.10\nmalicious.example.com\nmalicious@example.com\n198.51.100.0/24\n"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, feedData)
	}))
	t.Cleanup(server.Close)

	client := server.Client()
	client.Timeout = 5 * time.Second

	cfg := FeedConfig{
		Feeds: []Feed{
			{
				Name: "test_feed",
				URL:  server.URL,
				Type: []string{"suspicious", "c2"},
			},
		},
	}

	dataDir := filepath.Join(t.TempDir(), "intel")
	manager, err := NewManager(
		cfg,
		WithStorageDir(dataDir),
		WithHTTPClient(client),
		WithLogger(log.New(io.Discard, "", 0)),
		WithResolverTimeout(50*time.Millisecond),
		WithDNSCacheTTL(100*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	summary, err := manager.Hydrate(ctx)
	if err != nil {
		t.Fatalf("hydrate failed: %v", err)
	}

	if summary.SuccessfulFeeds != 1 {
		t.Fatalf("expected 1 successful feed, got %d", summary.SuccessfulFeeds)
	}
	if summary.TotalIndicators == 0 {
		t.Fatal("expected indicators to be ingested")
	}

	domainResult, err := manager.Check(context.Background(), CheckRequest{Domain: "malicious.example.com"})
	if err != nil {
		t.Fatalf("domain check failed: %v", err)
	}
	if len(domainResult.Matches) == 0 {
		t.Fatal("expected at least one match for domain")
	}
	if domainResult.Score <= 0 {
		t.Fatalf("expected positive score, got %d", domainResult.Score)
	}
	if domainResult.Summary.FeedCount == 0 {
		t.Fatal("expected feed summary for domain matches")
	}
	if len(domainResult.Summary.Feeds) == 0 {
		t.Fatal("expected feed names in summary")
	}

	emailResult, err := manager.Check(context.Background(), CheckRequest{Email: "malicious@example.com"})
	if err != nil {
		t.Fatalf("email check failed: %v", err)
	}
	if len(emailResult.Matches) == 0 {
		t.Fatal("expected email match")
	}
	if emailResult.Summary.FeedCount == 0 {
		t.Fatal("expected feed summary for email matches")
	}

	filteredResult, err := manager.Check(context.Background(), CheckRequest{
		Domain:             "malicious.example.com",
		IndicatorTypes:     []IndicatorType{IndicatorTypeDomain},
		IncludeResolvedIPs: false,
	})
	if err != nil {
		t.Fatalf("filtered domain check failed: %v", err)
	}
	if len(filteredResult.Matches) == 0 {
		t.Fatal("expected filtered match data")
	}
	for _, match := range filteredResult.Matches {
		if match.Type != IndicatorTypeDomain {
			t.Fatalf("expected only domain matches, found type %s", match.Type)
		}
	}
	if filteredResult.Summary.FeedCount != domainResult.Summary.FeedCount {
		t.Fatalf("expected filtered summary feed count to match domain summary, got %d", filteredResult.Summary.FeedCount)
	}
}

func TestManagerCheckBeforeHydrate(t *testing.T) {
	cfg := FeedConfig{
		Feeds: []Feed{
			{Name: "test", URL: "http://127.0.0.1/feed", Type: []string{"suspicious"}},
		},
	}

	manager, err := NewManager(
		cfg,
		WithStorageDir(t.TempDir()),
		WithLogger(log.New(io.Discard, "", 0)),
	)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	_, err = manager.Check(context.Background(), CheckRequest{Domain: "example.com"})
	if err == nil || err != ErrNotHydrated {
		t.Fatalf("expected ErrNotHydrated, got %v", err)
	}
}
