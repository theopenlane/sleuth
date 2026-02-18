package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/theopenlane/sleuth/internal/types"
)

const (
	// nucleiInitialBufSize is the initial buffer capacity for scanning nuclei output lines.
	nucleiInitialBufSize = 64 * 1024
	// nucleiMaxLineSize is the maximum line length accepted when parsing nuclei output.
	nucleiMaxLineSize = 2 * 1024 * 1024
)

// NucleiResult represents a single nuclei finding.
type NucleiResult struct {
	// TemplateID is the identifier of the nuclei template that matched.
	TemplateID string `json:"template-id"`
	// Info holds the template metadata for this finding.
	Info NucleiInfo `json:"info"`
	// Type is the type of match (e.g., http, dns, network).
	Type string `json:"type"`
	// Host is the target host that was scanned.
	Host string `json:"host"`
	// MatchedAt is the URL or endpoint where the vulnerability was found.
	MatchedAt string `json:"matched-at"`
	// ExtractedResults holds any data extracted by the template.
	ExtractedResults []string `json:"extracted-results,omitempty"`
	// Request is the raw HTTP request that triggered the finding.
	Request string `json:"request,omitempty"`
	// Response is the raw HTTP response from the target.
	Response string `json:"response,omitempty"`
	// CurlCommand is the curl equivalent of the request for reproduction.
	CurlCommand string `json:"curl-command,omitempty"`
	// Metadata holds additional key-value metadata about the finding.
	Metadata map[string]any `json:"metadata,omitempty"`
	// Timestamp is when the finding was detected.
	Timestamp time.Time `json:"timestamp"`
}

// NucleiInfo contains template metadata.
type NucleiInfo struct {
	// Name is the human-readable name of the nuclei template.
	Name string `json:"name"`
	// Author is the list of template authors.
	Author []string `json:"author"`
	// Tags is the list of tags categorizing the template.
	Tags []string `json:"tags"`
	// Description is the detailed description of what the template detects.
	Description string `json:"description"`
	// Reference holds external reference URLs for the vulnerability.
	Reference []string `json:"reference,omitempty"`
	// Severity is the severity level assigned by the template.
	Severity string `json:"severity"`
	// Metadata holds additional key-value metadata from the template.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// performNucleiScan runs nuclei vulnerability scanner against the domain.
func (s *Scanner) performNucleiScan(ctx context.Context, domain string) *types.CheckResult {
	result := newCheckResult("nuclei_scan")

	if !s.isNucleiAvailable(ctx) {
		result.Status = types.CheckStatusSkipped
		result.Error = "nuclei not available"
		return result
	}

	args := s.buildNucleiArgs(domain)
	cmdCtx, cancel := context.WithTimeout(ctx, s.options.NucleiTimeout)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, s.nucleiPath(), args...) //nolint:gosec // nuclei path from validated config, args constructed internally
	output, err := cmd.Output()
	if err != nil {
		if errors.Is(cmdCtx.Err(), context.DeadlineExceeded) {
			result.Status = types.CheckStatusTimeout
			result.Error = "nuclei scan timed out"
			return result
		}

		// Continue if we still got output to parse.
		if len(output) == 0 {
			markCheckError(result, "nuclei scan failed: %v", err)
			return result
		}
	}

	findings := s.parseNucleiOutput(string(output))
	for _, nucleiFinding := range findings {
		severity := s.mapNucleiSeverity(nucleiFinding.Info.Severity)
		result.Findings = append(result.Findings, types.Finding{
			Severity:    severity,
			Type:        "vulnerability",
			Description: fmt.Sprintf("%s: %s", nucleiFinding.Info.Name, nucleiFinding.Info.Description),
			Details: fmt.Sprintf("Template: %s | Host: %s | Matched: %s",
				nucleiFinding.TemplateID, nucleiFinding.Host, nucleiFinding.MatchedAt),
		})
	}

	if hasCriticalOrHigh(result.Findings) {
		markCheckFailed(result)
	}

	result.Metadata["total_findings"] = len(findings)
	result.Metadata["template_tags"] = s.options.NucleiTemplates
	result.Metadata["severity_filter"] = s.options.NucleiSeverity
	result.Metadata["scan_completed"] = cmdCtx.Err() == nil
	result.Metadata["nuclei_path"] = s.nucleiPath()

	return result
}

func hasCriticalOrHigh(findings []types.Finding) bool {
	for _, finding := range findings {
		if finding.Severity == "critical" || finding.Severity == "high" {
			return true
		}
	}
	return false
}

func (s *Scanner) nucleiPath() string {
	if s.options != nil && s.options.NucleiPath != "" {
		return s.options.NucleiPath
	}
	return defaultNucleiPath
}

// isNucleiAvailable checks if nuclei binary is available.
func (s *Scanner) isNucleiAvailable(ctx context.Context) bool {
	cmd := exec.CommandContext(ctx, s.nucleiPath(), "-version") //nolint:gosec // nuclei path from validated config
	return cmd.Run() == nil
}

// buildNucleiArgs constructs arguments for nuclei command.
func (s *Scanner) buildNucleiArgs(domain string) []string {
	args := []string{
		"-target", fmt.Sprintf("https://%s", domain),
		"-jsonl",
		"-silent",
		"-no-color",
		"-rate-limit", "10",
		"-timeout", "10",
		"-retries", "1",
	}

	if len(s.options.NucleiTemplates) > 0 {
		args = append(args, "-tags", strings.Join(s.options.NucleiTemplates, ","))
	}
	if len(s.options.NucleiSeverity) > 0 {
		args = append(args, "-severity", strings.Join(s.options.NucleiSeverity, ","))
	}

	args = append(args,
		"-exclude-tags", "dos,intrusive",
		"-header", "User-Agent: Sleuth-Security-Scanner/1.0",
	)

	return args
}

// parseNucleiOutput parses nuclei JSON output into structured results.
func (s *Scanner) parseNucleiOutput(output string) []NucleiResult {
	results := make([]NucleiResult, 0)
	scanner := bufio.NewScanner(strings.NewReader(output))
	scanner.Buffer(make([]byte, 0, nucleiInitialBufSize), nucleiMaxLineSize)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var parsed NucleiResult
		if err := json.Unmarshal([]byte(line), &parsed); err == nil {
			results = append(results, parsed)
		}
	}

	return results
}

// mapNucleiSeverity maps nuclei severity levels to our severity levels.
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
		return "medium"
	}
}

// GetNucleiVersion returns the version of nuclei if available.
func (s *Scanner) GetNucleiVersion(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(ctx, s.nucleiPath(), "-version") //nolint:gosec // nuclei path from validated config
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

// UpdateNucleiTemplates updates nuclei templates.
func (s *Scanner) UpdateNucleiTemplates(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, s.nucleiPath(), "-update-templates") //nolint:gosec // nuclei path from validated config
	return cmd.Run()
}
