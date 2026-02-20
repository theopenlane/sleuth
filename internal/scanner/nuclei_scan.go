package scanner

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"

	"github.com/theopenlane/sleuth/internal/types"
)

const (
	// nucleiRateLimit is the maximum requests per second for nuclei scanning.
	nucleiRateLimit = 500
	// nucleiNetworkTimeout is the per-request timeout in seconds for nuclei.
	nucleiNetworkTimeout = 10
	// nucleiNetworkRetries is the number of retries for nuclei network requests.
	nucleiNetworkRetries = 1
	// nucleiTemplateConcurrency is the number of templates to run concurrently.
	nucleiTemplateConcurrency = 25
	// nucleiHostConcurrency is the number of hosts to scan concurrently.
	nucleiHostConcurrency = 5
	// nucleiHeadlessConcurrency is the default concurrency for headless operations.
	nucleiHeadlessConcurrency = 5
	// nucleiJSConcurrency is the default concurrency for javascript templates.
	nucleiJSConcurrency = 5
	// nucleiPayloadConcurrency is the max concurrent payloads per template.
	nucleiPayloadConcurrency = 25
	// nucleiProbeConcurrency is the max concurrent HTTP probes.
	nucleiProbeConcurrency = 50
)

// initNucleiEngine creates a persistent, thread-safe nuclei engine with templates
// preloaded at server startup. Only thread-safe options are set here; per-execution
// options (network config, verbosity) are passed via ExecuteNucleiWithOptsCtx.
func (s *Scanner) initNucleiEngine() (*nuclei.ThreadSafeNucleiEngine, error) {
	opts := []nuclei.NucleiSDKOptions{
		nuclei.DisableUpdateCheck(),
		nuclei.WithTemplateFilters(nuclei.TemplateFilters{
			Severity:    strings.Join(s.options.NucleiSeverity, ","),
			Tags:        s.options.NucleiTemplates,
			ExcludeTags: []string{"dos", "intrusive"},
		}),
		nuclei.WithConcurrency(nuclei.Concurrency{
			TemplateConcurrency:           nucleiTemplateConcurrency,
			HostConcurrency:               nucleiHostConcurrency,
			HeadlessHostConcurrency:       nucleiHeadlessConcurrency,
			HeadlessTemplateConcurrency:   nucleiHeadlessConcurrency,
			JavascriptTemplateConcurrency: nucleiJSConcurrency,
			TemplatePayloadConcurrency:    nucleiPayloadConcurrency,
			ProbeConcurrency:              nucleiProbeConcurrency,
		}),
		nuclei.WithGlobalRateLimit(nucleiRateLimit, time.Second),
		nuclei.WithHeaders([]string{"User-Agent: Sleuth-Security-Scanner/1.0"}),
	}

	engine, err := nuclei.NewThreadSafeNucleiEngineCtx(context.Background(), opts...)
	if err != nil {
		return nil, fmt.Errorf("creating thread-safe nuclei engine: %w", err)
	}

	if err := engine.GlobalLoadAllTemplates(); err != nil {
		engine.Close()
		return nil, fmt.Errorf("preloading nuclei templates: %w", err)
	}

	return engine, nil
}

// performNucleiScan runs nuclei vulnerability scanner against the domain using
// the pre-initialized thread-safe engine.
func (s *Scanner) performNucleiScan(ctx context.Context, domain string) *types.CheckResult {
	result := newCheckResult("nuclei_scan")

	if s.nucleiEngine == nil {
		result.Status = types.CheckStatusSkipped
		result.Error = "nuclei engine not initialized"

		return result
	}

	scanCtx, cancel := context.WithTimeout(ctx, s.options.NucleiTimeout)
	defer cancel()

	target := fmt.Sprintf("https://%s", domain)

	var (
		mu       sync.Mutex
		findings []types.Finding
	)

	s.nucleiEngine.GlobalResultCallback(func(event *output.ResultEvent) {
		severity := mapNucleiSeverity(event.Info.SeverityHolder.Severity.String())

		description := strings.TrimSpace(event.Info.Name)
		if event.MatcherName != "" {
			description = fmt.Sprintf("%s: %s", description, event.MatcherName)
		}

		if trimmed := strings.TrimSpace(event.Info.Description); trimmed != "" {
			description = fmt.Sprintf("%s -- %s", description, trimmed)
		}

		finding := types.Finding{
			Severity:    severity,
			Type:        "vulnerability",
			Description: description,
			Details: fmt.Sprintf("Template: %s | Host: %s | Matched: %s",
				event.TemplateID, event.Host, event.Matched),
		}

		mu.Lock()
		findings = append(findings, finding)
		mu.Unlock()
	})

	// Per-execution options that are not thread-safe at init time
	execOpts := []nuclei.NucleiSDKOptions{
		nuclei.WithNetworkConfig(nuclei.NetworkConfig{
			Timeout: nucleiNetworkTimeout,
			Retries: nucleiNetworkRetries,
		}),
	}

	err := s.nucleiEngine.ExecuteNucleiWithOptsCtx(scanCtx, []string{target}, execOpts...)
	if err != nil {
		if scanCtx.Err() != nil {
			result.Status = types.CheckStatusTimeout
			result.Error = "nuclei scan timed out"

			return result
		}

		markCheckError(result, "nuclei scan failed: %v", err)

		return result
	}

	result.Findings = findings

	if hasCriticalOrHigh(result.Findings) {
		markCheckFailed(result)
	}

	result.Metadata["total_findings"] = len(findings)
	result.Metadata["template_tags"] = s.options.NucleiTemplates
	result.Metadata["severity_filter"] = s.options.NucleiSeverity
	result.Metadata["scan_completed"] = scanCtx.Err() == nil

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

// mapNucleiSeverity maps nuclei severity levels to internal severity levels.
func mapNucleiSeverity(nucleiSeverity string) string {
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
