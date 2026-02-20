package intel

import (
	"testing"
)

func TestSanitizeLine(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{"example.com", "example.com"},
		{"example.com # comment", "example.com"},
		{"example.com ; semicolon comment", "example.com"},
		{"  example.com  ", "example.com"},
		{"# full comment line", ""},
		{"; full semicolon line", ""},
		{"", ""},
		{"   ", ""},
		{"example.com#inline", "example.com"},
		{"example.com;inline", "example.com"},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := sanitizeLine(tc.input)
			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}

func TestIsPrivateOrInvalidIP(t *testing.T) {
	testCases := []struct {
		name     string
		ip       string
		expected bool
	}{
		{"public ipv4", "8.8.8.8", false},
		{"public ipv4 2", "1.1.1.1", false},
		{"private 10.x", "10.0.0.1", true},
		{"private 192.168.x", "192.168.1.1", true},
		{"private 172.16.x", "172.16.0.1", true},
		{"private 172.31.x", "172.31.255.255", true},
		{"loopback", "127.0.0.1", true},
		{"zero", "0.0.0.0", true},
		{"broadcast", "255.255.255.255", true},
		{"ipv6 loopback", "::1", true},
		{"ipv6 unspecified", "::", true},
		{"ipv6 public", "2001:4860:4860::8888", false},
		{"link local", "169.254.0.1", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			val, _ := parseIndicator(tc.ip)
			result := (val == "")
			if result != tc.expected {
				t.Errorf("for IP %s, expected private/invalid=%v, got %v", tc.ip, tc.expected, result)
			}
		})
	}
}

func TestParseIndicatorURL(t *testing.T) {
	testCases := []struct {
		name          string
		input         string
		expectedValue string
		expectedType  IndicatorType
	}{
		{"https url", "https://evil.example.com/phish", "evil.example.com", IndicatorTypeDomain},
		{"http url", "http://malware.badsite.org/payload.exe", "malware.badsite.org", IndicatorTypeDomain},
		{"url with port", "https://phish.test.io:8443/login", "phish.test.io", IndicatorTypeDomain},
		{"url with path and query", "https://scam.example.net/page?id=1", "scam.example.net", IndicatorTypeDomain},
		{"bare domain still works", "example.com", "example.com", IndicatorTypeDomain},
		{"ip address still works", "8.8.8.8", "8.8.8.8", IndicatorTypeIP},
		{"url with ip host", "http://93.184.216.34/malware", "93.184.216.34", IndicatorTypeIP},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			value, typ := parseIndicator(tc.input)
			if value != tc.expectedValue {
				t.Errorf("expected value %q, got %q", tc.expectedValue, value)
			}
			if typ != tc.expectedType {
				t.Errorf("expected type %q, got %q", tc.expectedType, typ)
			}
		})
	}
}

func TestSplitFields(t *testing.T) {
	testCases := []struct {
		input    string
		expected []string
	}{
		{"single", []string{"single"}},
		{"two fields", []string{"two", "fields"}},
		{"comma,separated", []string{"comma", "separated"}},
		{"semicolon;separated", []string{"semicolon", "separated"}},
		{"pipe|separated", []string{"pipe", "separated"}},
		{"mixed,delimiters;here|now", []string{"mixed", "delimiters", "here", "now"}},
		{"tabs\there", []string{"tabs", "here"}},
		{"  spaces  everywhere  ", []string{"spaces", "everywhere"}},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := splitFields(tc.input)
			if len(result) != len(tc.expected) {
				t.Fatalf("expected %d fields, got %d", len(tc.expected), len(result))
			}
			for i := range result {
				if result[i] != tc.expected[i] {
					t.Errorf("field %d: expected %q, got %q", i, tc.expected[i], result[i])
				}
			}
		})
	}
}
