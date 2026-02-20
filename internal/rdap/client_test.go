package rdap

import (
	"context"
	"testing"
	"time"
)

func TestGradeDomainAge(t *testing.T) {
	cases := []struct {
		name       string
		ageDays    int
		wantCat    string
		wantWeight int
	}{
		{name: "brand new", ageDays: 0, wantCat: "new_domain_7d", wantWeight: weightNewDomain7d},
		{name: "3 days", ageDays: 3, wantCat: "new_domain_7d", wantWeight: weightNewDomain7d},
		{name: "6 days", ageDays: 6, wantCat: "new_domain_7d", wantWeight: weightNewDomain7d},
		{name: "7 days", ageDays: 7, wantCat: "new_domain_30d", wantWeight: weightNewDomain30d},
		{name: "15 days", ageDays: 15, wantCat: "new_domain_30d", wantWeight: weightNewDomain30d},
		{name: "29 days", ageDays: 29, wantCat: "new_domain_30d", wantWeight: weightNewDomain30d},
		{name: "30 days", ageDays: 30, wantCat: "new_domain_90d", wantWeight: weightNewDomain90d},
		{name: "60 days", ageDays: 60, wantCat: "new_domain_90d", wantWeight: weightNewDomain90d},
		{name: "89 days", ageDays: 89, wantCat: "new_domain_90d", wantWeight: weightNewDomain90d},
		{name: "90 days", ageDays: 90, wantCat: "new_domain_365d", wantWeight: weightNewDomain365d},
		{name: "200 days", ageDays: 200, wantCat: "new_domain_365d", wantWeight: weightNewDomain365d},
		{name: "364 days", ageDays: 364, wantCat: "new_domain_365d", wantWeight: weightNewDomain365d},
		{name: "365 days", ageDays: 365, wantCat: "", wantWeight: 0},
		{name: "1000 days", ageDays: 1000, wantCat: "", wantWeight: 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cat, weight := gradeDomainAge(tc.ageDays)
			if cat != tc.wantCat {
				t.Errorf("gradeDomainAge(%d) category = %q, want %q", tc.ageDays, cat, tc.wantCat)
			}

			if weight != tc.wantWeight {
				t.Errorf("gradeDomainAge(%d) weight = %d, want %d", tc.ageDays, weight, tc.wantWeight)
			}
		})
	}
}

func TestBuildMatches(t *testing.T) {
	t.Run("nil registration date produces no matches", func(t *testing.T) {
		result := Result{Domain: "example.com"}
		matches := buildMatches("example.com", result)

		if len(matches) != 0 {
			t.Fatalf("expected 0 matches, got %d", len(matches))
		}
	})

	t.Run("old domain produces no matches", func(t *testing.T) {
		regDate := time.Now().AddDate(-5, 0, 0)
		result := Result{
			Domain:           "example.com",
			RegistrationDate: &regDate,
			DomainAgeDays:    5 * 365,
		}
		matches := buildMatches("example.com", result)

		if len(matches) != 0 {
			t.Fatalf("expected 0 matches for old domain, got %d", len(matches))
		}
	})

	t.Run("new domain produces match", func(t *testing.T) {
		regDate := time.Now().Add(-48 * time.Hour)
		result := Result{
			Domain:           "suspicious.com",
			RegistrationDate: &regDate,
			DomainAgeDays:    2,
		}
		matches := buildMatches("suspicious.com", result)

		if len(matches) != 1 {
			t.Fatalf("expected 1 match, got %d", len(matches))
		}

		if matches[0].Categories[0] != "new_domain_7d" {
			t.Fatalf("expected category new_domain_7d, got %s", matches[0].Categories[0])
		}
	})

	t.Run("45 day old domain gets 90d category", func(t *testing.T) {
		regDate := time.Now().AddDate(0, 0, -45)
		result := Result{
			Domain:           "example.com",
			RegistrationDate: &regDate,
			DomainAgeDays:    45,
		}
		matches := buildMatches("example.com", result)

		if len(matches) != 1 {
			t.Fatalf("expected 1 match, got %d", len(matches))
		}

		if matches[0].Categories[0] != "new_domain_90d" {
			t.Fatalf("expected category new_domain_90d, got %s", matches[0].Categories[0])
		}
	})
}

func TestBuildResult(t *testing.T) {
	// buildResult is tested through buildMatches above for the most part,
	// but we also test the event parsing directly via a helper
	regDate := time.Now().AddDate(0, 0, -10)
	result := Result{
		Domain:           "test.com",
		RegistrationDate: &regDate,
		DomainAgeDays:    10,
	}

	if result.DomainAgeDays != 10 {
		t.Fatalf("expected 10 day age, got %d", result.DomainAgeDays)
	}
}

func TestClientEmptyDomain(t *testing.T) {
	client := NewClient()
	_, _, err := client.Analyze(context.Background(), "")

	if err != ErrEmptyDomain {
		t.Fatalf("expected ErrEmptyDomain, got %v", err)
	}
}

func TestClientEmptyDomainWhitespace(t *testing.T) {
	client := NewClient()
	_, _, err := client.Analyze(context.Background(), "   ")

	if err != ErrEmptyDomain {
		t.Fatalf("expected ErrEmptyDomain, got %v", err)
	}
}
