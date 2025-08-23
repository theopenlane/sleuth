package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/theopenlane/sleuth/internal/types"
)

// NucleiResult represents a single nuclei finding
type NucleiResult struct {
	TemplateID   string                 `json:"template-id"`
	Info         NucleiInfo             `json:"info"`
	Type         string                 `json:"type"`
	Host         string                 `json:"host"`
	MatchedAt    string                 `json:"matched-at"`
	ExtractedResults []string           `json:"extracted-results,omitempty"`
	Request      string                 `json:"request,omitempty"`
	Response     string                 `json:"response,omitempty"`
	CurlCommand  string                 `json:"curl-command,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	Timestamp    time.Time              `json:"timestamp"`
}

// NucleiInfo contains template metadata
type NucleiInfo struct {
	Name        string            `json:"name"`
	Author      []string          `json:"author"`
	Tags        []string          `json:"tags"`
	Description string            `json:"description"`
	Reference   []string          `json:"reference,omitempty"`
	Severity    string            `json:"severity"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// performNucleiScan runs nuclei vulnerability scanner against the domain
func (s *Scanner) performNucleiScan(ctx context.Context, domain string) *types.CheckResult {
	result := &types.CheckResult{
		CheckName: "nuclei_scan",
		Status:    "pass",
		Findings:  []types.Finding{},
		Metadata:  make(map[string]interface{}),
	}

	// Check if nuclei is available
	if !s.isNucleiAvailable() {
		result.Status = "skipped"
		result.Error = "nuclei not available"
		return result
	}

	// Build nuclei command
	args := s.buildNucleiArgs(domain)
	
	// Create command with timeout
	cmdCtx, cancel := context.WithTimeout(ctx, s.options.NucleiTimeout)
	defer cancel()
	
	cmd := exec.CommandContext(cmdCtx, "nuclei", args...)
	
	// Run nuclei and capture output
	output, err := cmd.Output()
	if err != nil {
		// Nuclei might return non-zero exit code even on successful scans
		if cmdCtx.Err() == context.DeadlineExceeded {
			result.Status = "timeout"
			result.Error = "nuclei scan timed out"
			return result
		}
		// Continue processing even if there's an error, as we might still have output
	}

	// Parse nuclei JSON output
	findings := s.parseNucleiOutput(string(output))
	
	// Convert nuclei results to our finding format
	for _, nucleiResult := range findings {
		severity := s.mapNucleiSeverity(nucleiResult.Info.Severity)
		
		result.Findings = append(result.Findings, types.Finding{
			Severity:    severity,
			Type:        "vulnerability",
			Description: fmt.Sprintf("%s: %s", nucleiResult.Info.Name, nucleiResult.Info.Description),
			Details:     fmt.Sprintf("Template: %s | Host: %s | Matched: %s", 
				nucleiResult.TemplateID, nucleiResult.Host, nucleiResult.MatchedAt),
		})
	}

	// Set status based on findings
	if len(result.Findings) > 0 {
		hasCriticalOrHigh := false
		for _, finding := range result.Findings {
			if finding.Severity == "critical" || finding.Severity == "high" {
				hasCriticalOrHigh = true
				break
			}
		}
		if hasCriticalOrHigh {
			result.Status = "fail"
		}
	}

	result.Metadata["total_findings"] = len(findings)
	result.Metadata["templates_used"] = s.options.NucleiTemplates
	result.Metadata["severity_filter"] = s.options.NucleiSeverity

	return result
}

// isNucleiAvailable checks if nuclei binary is available
func (s *Scanner) isNucleiAvailable() bool {
	cmd := exec.Command("nuclei", "-version")
	return cmd.Run() == nil
}

// buildNucleiArgs constructs arguments for nuclei command
func (s *Scanner) buildNucleiArgs(domain string) []string {
	args := []string{
		"-target", fmt.Sprintf("https://%s", domain),
		"-json",                    // JSON output format
		"-silent",                  // Reduce noise
		"-no-color",               // No ANSI colors in output
		"-rate-limit", "10",       // Rate limiting to be respectful
		"-timeout", "10",          // Per-request timeout
		"-retries", "1",           // Number of retries
	}

	// Add template filters
	if len(s.options.NucleiTemplates) > 0 {
		args = append(args, "-tags", strings.Join(s.options.NucleiTemplates, ","))
	}

	// Add severity filter
	if len(s.options.NucleiSeverity) > 0 {
		args = append(args, "-severity", strings.Join(s.options.NucleiSeverity, ","))
	}

	// Add additional safety measures
	args = append(args,
		"-exclude-tags", "dos,intrusive", // Exclude potentially disruptive tests
		"-header", "User-Agent: Sleuth-Security-Scanner/1.0",
	)

	return args
}

// parseNucleiOutput parses nuclei JSON output into structured results
func (s *Scanner) parseNucleiOutput(output string) []NucleiResult {
	var results []NucleiResult
	
	// Nuclei outputs one JSON object per line
	lines := strings.Split(strings.TrimSpace(output), "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		
		var result NucleiResult
		if err := json.Unmarshal([]byte(line), &result); err == nil {
			results = append(results, result)
		}
	}
	
	return results
}

// mapNucleiSeverity maps nuclei severity levels to our severity levels
func (s *Scanner) mapNucleiSeverity(nucleiSeverity string) string {
	switch strings.ToLower(nucleiSeverity) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	case "info", "informational":
		return "info"
	default:
		return "medium" // Default to medium for unknown severities
	}
}

// GetNucleiVersion returns the version of nuclei if available
func (s *Scanner) GetNucleiVersion() (string, error) {
	cmd := exec.Command("nuclei", "-version")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

// UpdateNucleiTemplates updates nuclei templates
func (s *Scanner) UpdateNucleiTemplates(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "nuclei", "-update-templates")
	return cmd.Run()
}