package domain

import (
	"testing"
)

func TestParse(t *testing.T) {
	testCases := []struct {
		name      string
		input     string
		wantDom   string
		wantSub   string
		wantTLD   string
		wantSLD   string
		wantError bool
	}{
		{
			name:    "simple domain",
			input:   "example.com",
			wantDom: "example.com",
			wantSub: "",
			wantTLD: "com",
			wantSLD: "example",
		},
		{
			name:    "subdomain",
			input:   "www.example.com",
			wantDom: "www.example.com",
			wantSub: "www",
			wantTLD: "com",
			wantSLD: "example",
		},
		{
			name:    "nested subdomain",
			input:   "api.staging.example.com",
			wantDom: "api.staging.example.com",
			wantSub: "api.staging",
			wantTLD: "com",
			wantSLD: "example",
		},
		{
			name:    "co.uk tld",
			input:   "example.co.uk",
			wantDom: "example.co.uk",
			wantSub: "",
			wantTLD: "co.uk",
			wantSLD: "example",
		},
		{
			name:    "subdomain with co.uk",
			input:   "www.example.co.uk",
			wantDom: "www.example.co.uk",
			wantSub: "www",
			wantTLD: "co.uk",
			wantSLD: "example",
		},
		{
			name:    "email address",
			input:   "user@example.com",
			wantDom: "example.com",
			wantSub: "",
			wantTLD: "com",
			wantSLD: "example",
		},
		{
			name:    "email with subdomain",
			input:   "user@mail.example.com",
			wantDom: "mail.example.com",
			wantSub: "mail",
			wantTLD: "com",
			wantSLD: "example",
		},
		{
			name:    "http url",
			input:   "http://example.com",
			wantDom: "example.com",
			wantSub: "",
			wantTLD: "com",
			wantSLD: "example",
		},
		{
			name:    "https url",
			input:   "https://www.example.com",
			wantDom: "www.example.com",
			wantSub: "www",
			wantTLD: "com",
			wantSLD: "example",
		},
		{
			name:    "url with path",
			input:   "https://example.com/path/to/resource",
			wantDom: "example.com",
			wantSub: "",
			wantTLD: "com",
			wantSLD: "example",
		},
		{
			name:    "domain with port",
			input:   "example.com:8080",
			wantDom: "example.com",
			wantSub: "",
			wantTLD: "com",
			wantSLD: "example",
		},
		{
			name:    "subdomain with port",
			input:   "api.example.com:443",
			wantDom: "api.example.com",
			wantSub: "api",
			wantTLD: "com",
			wantSLD: "example",
		},
		{
			name:    "mixed case domain",
			input:   "Example.COM",
			wantDom: "example.com",
			wantSub: "",
			wantTLD: "com",
			wantSLD: "example",
		},
		{
			name:    "domain with whitespace",
			input:   "  example.com  ",
			wantDom: "example.com",
			wantSub: "",
			wantTLD: "com",
			wantSLD: "example",
		},
		{
			name:      "invalid - no tld",
			input:     "example",
			wantError: true,
		},
		{
			name:      "invalid - empty string",
			input:     "",
			wantError: true,
		},
		{
			name:      "invalid - multiple @ signs",
			input:     "user@@example.com",
			wantError: true,
		},
		{
			name:      "invalid - just tld",
			input:     ".com",
			wantError: true,
		},
		{
			name:      "invalid - malformed url",
			input:     "http://",
			wantError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			info, err := Parse(tc.input)

			if tc.wantError {
				if err == nil {
					t.Errorf("expected error for input %q, got nil", tc.input)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if info.Domain != tc.wantDom {
				t.Errorf("domain: expected %q, got %q", tc.wantDom, info.Domain)
			}
			if info.Subdomain != tc.wantSub {
				t.Errorf("subdomain: expected %q, got %q", tc.wantSub, info.Subdomain)
			}
			if info.TLD != tc.wantTLD {
				t.Errorf("tld: expected %q, got %q", tc.wantTLD, info.TLD)
			}
			if info.SLD != tc.wantSLD {
				t.Errorf("sld: expected %q, got %q", tc.wantSLD, info.SLD)
			}
		})
	}
}

func TestParseEmailExtraction(t *testing.T) {
	testCases := []struct {
		email    string
		expected string
	}{
		{"user@example.com", "example.com"},
		{"admin@subdomain.example.com", "subdomain.example.com"},
		{"test.user@example.co.uk", "example.co.uk"},
		{"test+tag@example.com", "example.com"},
	}

	for _, tc := range testCases {
		t.Run(tc.email, func(t *testing.T) {
			info, err := Parse(tc.email)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if info.Domain != tc.expected {
				t.Errorf("expected domain %q, got %q", tc.expected, info.Domain)
			}
		})
	}
}

func TestParseURLExtraction(t *testing.T) {
	testCases := []struct {
		url      string
		expected string
	}{
		{"http://example.com", "example.com"},
		{"https://www.example.com", "www.example.com"},
		{"https://api.example.com:443/v1/endpoint", "api.example.com"},
		{"http://localhost:8080", "localhost"},
	}

	for _, tc := range testCases {
		t.Run(tc.url, func(t *testing.T) {
			info, err := Parse(tc.url)
			if err != nil && tc.expected != "localhost" {
				t.Fatalf("unexpected error: %v", err)
			}
			if err == nil && info.Domain != tc.expected {
				t.Errorf("expected domain %q, got %q", tc.expected, info.Domain)
			}
		})
	}
}
