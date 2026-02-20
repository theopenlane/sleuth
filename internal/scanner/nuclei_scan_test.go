package scanner

import (
	"testing"

	"github.com/theopenlane/sleuth/internal/types"
)

func TestMapNucleiSeverity(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{"critical", "critical"},
		{"high", "high"},
		{"medium", "medium"},
		{"low", "low"},
		{"info", "info"},
		{"informational", "info"},
		{"unknown", "medium"},
		{"CRITICAL", "critical"},
		{"HIGH", "high"},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := mapNucleiSeverity(tc.input)
			if result != tc.expected {
				t.Errorf("Expected severity %s for input %s, got %s",
					tc.expected, tc.input, result)
			}
		})
	}
}

func TestHasCriticalOrHigh(t *testing.T) {
	tests := []struct {
		name     string
		findings []types.Finding
		expected bool
	}{
		{
			name:     "empty",
			findings: nil,
			expected: false,
		},
		{
			name:     "info only",
			findings: []types.Finding{{Severity: "info"}},
			expected: false,
		},
		{
			name:     "medium only",
			findings: []types.Finding{{Severity: "medium"}},
			expected: false,
		},
		{
			name:     "has high",
			findings: []types.Finding{{Severity: "info"}, {Severity: "high"}},
			expected: true,
		},
		{
			name:     "has critical",
			findings: []types.Finding{{Severity: "critical"}},
			expected: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := hasCriticalOrHigh(tc.findings)
			if got != tc.expected {
				t.Errorf("hasCriticalOrHigh() = %v, expected %v", got, tc.expected)
			}
		})
	}
}
