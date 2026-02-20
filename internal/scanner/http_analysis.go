package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/theopenlane/sleuth/internal/types"
)

const (
	// httpRedirectLimit is the maximum number of redirects allowed during HTTP analysis.
	httpRedirectLimit = 10
	// bodyReadLimit is the maximum number of bytes to read from an HTTP response body.
	bodyReadLimit = 100 * 1024
	// missingHeaderThreshold is the number of missing required security headers that triggers a fail status.
	missingHeaderThreshold = 2
)

// performHTTPAnalysis analyzes HTTP services and security headers.
func (s *Scanner) performHTTPAnalysis(ctx context.Context, domain string) *types.CheckResult {
	result := newCheckResult("http_analysis")

	client := &http.Client{
		Timeout: s.options.HTTPTimeout,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= httpRedirectLimit {
				return ErrTooManyRedirects
			}
			return nil
		},
	}

	protocols := []string{"https", "http"}
	var (
		resp     *http.Response
		err      error
		finalURL string
	)

	retries := s.options.HTTPRetries + 1
	if retries < 1 {
		retries = 1
	}

	for _, protocol := range protocols {
		url := fmt.Sprintf("%s://%s", protocol, domain)
		for attempt := 0; attempt < retries; attempt++ {
			req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if reqErr != nil {
				err = reqErr
				break
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Sleuth/1.0)")

			resp, err = client.Do(req)
			if err == nil {
				finalURL = resp.Request.URL.String()
				break
			}
			if ctx.Err() != nil {
				break
			}
		}
		if resp != nil {
			break
		}
	}

	if err != nil || resp == nil {
		markCheckError(result, "HTTP request failed: %v", err)
		return result
	}
	defer func() { _ = resp.Body.Close() }()

	result.Metadata["final_url"] = finalURL
	result.Metadata["status_code"] = resp.StatusCode
	result.Metadata["protocol"] = resp.Request.URL.Scheme
	result.Metadata["retries"] = retries

	s.analyzeSecurityHeaders(resp, result)

	if resp.Request.URL.Scheme == "https" {
		s.analyzeTLSWithTLSX(domain, result)
	}

	bodyBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, bodyReadLimit))
	if readErr == nil {
		body := string(bodyBytes)
		s.analyzeResponseBody(body, result)
	}

	return result
}

// analyzeSecurityHeaders checks for security-related HTTP headers.
func (s *Scanner) analyzeSecurityHeaders(resp *http.Response, result *types.CheckResult) {
	headers := map[string]struct {
		Required bool
		Severity string
		Check    func(string) (bool, string)
	}{
		"Strict-Transport-Security": {
			Required: true,
			Severity: "high",
			Check: func(value string) (bool, string) {
				if value == "" {
					return false, "Missing HSTS header - vulnerable to protocol downgrade attacks"
				}
				if !strings.Contains(value, "max-age=") {
					return false, "HSTS header missing max-age directive"
				}
				return true, ""
			},
		},
		"X-Frame-Options": {
			Required: true,
			Severity: "medium",
			Check: func(value string) (bool, string) {
				if value == "" {
					return false, "Missing X-Frame-Options header - vulnerable to clickjacking"
				}
				value = strings.ToUpper(value)
				if value != "DENY" && value != "SAMEORIGIN" {
					return false, fmt.Sprintf("X-Frame-Options has weak value: %s", value)
				}
				return true, ""
			},
		},
		"X-Content-Type-Options": {
			Required: true,
			Severity: "medium",
			Check: func(value string) (bool, string) {
				if value == "" {
					return false, "Missing X-Content-Type-Options header"
				}
				if strings.ToLower(value) != "nosniff" {
					return false, fmt.Sprintf("X-Content-Type-Options should be 'nosniff', got: %s", value)
				}
				return true, ""
			},
		},
		"Content-Security-Policy": {
			Required: false,
			Severity: "medium",
			Check: func(value string) (bool, string) {
				if value == "" {
					return false, "Missing Content-Security-Policy header"
				}
				if strings.Contains(value, "unsafe-inline") || strings.Contains(value, "unsafe-eval") {
					return false, "CSP contains unsafe directives"
				}
				return true, ""
			},
		},
		"Referrer-Policy": {
			Required: false,
			Severity: "low",
			Check: func(value string) (bool, string) {
				if value == "" {
					return false, "Missing Referrer-Policy header"
				}
				return true, ""
			},
		},
	}

	presentHeaders := make(map[string]string)
	missingCount := 0

	for header, config := range headers {
		value := resp.Header.Get(header)
		if value != "" {
			presentHeaders[header] = value
		}

		if ok, issue := config.Check(value); !ok {
			if config.Required {
				missingCount++
			}

			result.Findings = append(result.Findings, types.Finding{
				Severity:    config.Severity,
				Type:        "security_header",
				Description: issue,
				Details:     fmt.Sprintf("Header: %s", header),
			})
		}
	}

	result.Metadata["security_headers"] = presentHeaders
	result.Metadata["security_score"] = fmt.Sprintf("%d/%d headers configured",
		len(presentHeaders), len(headers))

	if missingCount > missingHeaderThreshold {
		markCheckFailed(result)
	}
}

// analyzeResponseBody analyzes the HTTP response body for issues.
func (s *Scanner) analyzeResponseBody(body string, result *types.CheckResult) {
	bodyLower := strings.ToLower(body)

	errorPatterns := map[string]string{
		"stack trace":    "Stack trace exposed",
		"database error": "Database error exposed",
		"php warning":    "PHP warning exposed",
		"php error":      "PHP error exposed",
		"sql syntax":     "SQL error exposed",
		"apache/":        "Apache version disclosed",
		"nginx/":         "Nginx version disclosed",
	}

	for pattern, description := range errorPatterns {
		if strings.Contains(bodyLower, pattern) {
			result.Findings = append(result.Findings, types.Finding{
				Severity:    "medium",
				Type:        "information_disclosure",
				Description: description,
				Details:     "Found in response body",
			})
		}
	}
}
