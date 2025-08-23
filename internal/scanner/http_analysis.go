package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/theopenlane/sleuth/internal/types"
)

// performHTTPAnalysis analyzes HTTP services and security headers
func (s *Scanner) performHTTPAnalysis(ctx context.Context, domain string) *types.CheckResult {
	result := &types.CheckResult{
		CheckName: "http_analysis",
		Status:    "pass",
		Findings:  []types.Finding{},
		Metadata:  make(map[string]interface{}),
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: s.options.HTTPTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	// Try HTTPS first, then HTTP
	protocols := []string{"https", "http"}
	var resp *http.Response
	var err error
	var finalURL string

	for _, protocol := range protocols {
		url := fmt.Sprintf("%s://%s", protocol, domain)
		req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Sleuth/1.0)")

		resp, err = client.Do(req)
		if err == nil {
			finalURL = resp.Request.URL.String()
			defer func() { _ = resp.Body.Close() }()
			break
		}
	}

	if err != nil {
		result.Status = "error"
		result.Error = fmt.Sprintf("HTTP request failed: %v", err)
		return result
	}

	result.Metadata["final_url"] = finalURL
	result.Metadata["status_code"] = resp.StatusCode
	result.Metadata["protocol"] = resp.Request.URL.Scheme

	// Analyze security headers
	s.analyzeSecurityHeaders(resp, result)

	// Analyze TLS if HTTPS
	if resp.TLS != nil {
		s.analyzeTLSConfiguration(resp.TLS, result)
	}

	// Read and analyze response body (limited)
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 100*1024)) // 100KB limit
	if err == nil {
		body := string(bodyBytes)
		s.analyzeResponseBody(body, result)
		s.detectTechnologies(body, resp.Header, result)
	}

	// Check for common exposed files
	s.checkExposedFiles(ctx, domain, client, result)

	return result
}

// analyzeSecurityHeaders checks for security-related HTTP headers
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

	if missingCount > 2 {
		result.Status = "fail"
	}
}

// analyzeTLSConfiguration analyzes TLS/SSL configuration
func (s *Scanner) analyzeTLSConfiguration(tlsState *tls.ConnectionState, result *types.CheckResult) {
	tlsInfo := make(map[string]interface{})

	// TLS version analysis
	tlsVersion := "Unknown"
	switch tlsState.Version {
	case tls.VersionTLS10:
		tlsVersion = "TLS 1.0"
		result.Findings = append(result.Findings, types.Finding{
			Severity:    "critical",
			Type:        "weak_tls",
			Description: "Outdated TLS 1.0 in use",
			Details:     "TLS 1.0 is deprecated and has known vulnerabilities",
		})
	case tls.VersionTLS11:
		tlsVersion = "TLS 1.1"
		result.Findings = append(result.Findings, types.Finding{
			Severity:    "high",
			Type:        "weak_tls",
			Description: "Outdated TLS 1.1 in use",
			Details:     "TLS 1.1 is deprecated and should be upgraded",
		})
	case tls.VersionTLS12:
		tlsVersion = "TLS 1.2"
	case tls.VersionTLS13:
		tlsVersion = "TLS 1.3"
	}

	tlsInfo["version"] = tlsVersion
	tlsInfo["cipher_suite"] = tls.CipherSuiteName(tlsState.CipherSuite)

	// Certificate analysis
	if len(tlsState.PeerCertificates) > 0 {
		cert := tlsState.PeerCertificates[0]
		certInfo := map[string]interface{}{
			"subject":    cert.Subject.String(),
			"issuer":     cert.Issuer.String(),
			"not_before": cert.NotBefore.Format(time.RFC3339),
			"not_after":  cert.NotAfter.Format(time.RFC3339),
			"dns_names":  cert.DNSNames,
		}

		// Check certificate expiration
		daysUntilExpiry := int(time.Until(cert.NotAfter).Hours() / 24)
		if daysUntilExpiry < 0 {
			result.Findings = append(result.Findings, types.Finding{
				Severity:    "critical",
				Type:        "expired_certificate",
				Description: "SSL certificate has expired",
				Details:     fmt.Sprintf("Expired %d days ago", -daysUntilExpiry),
			})
		} else if daysUntilExpiry < 30 {
			result.Findings = append(result.Findings, types.Finding{
				Severity:    "high",
				Type:        "expiring_certificate",
				Description: "SSL certificate expiring soon",
				Details:     fmt.Sprintf("Expires in %d days", daysUntilExpiry),
			})
		}

		tlsInfo["certificate"] = certInfo
	}

	result.Metadata["tls"] = tlsInfo
}

// analyzeResponseBody analyzes the HTTP response body for issues
func (s *Scanner) analyzeResponseBody(body string, result *types.CheckResult) {
	bodyLower := strings.ToLower(body)

	// Check for error pages that might reveal information
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

// checkExposedFiles checks for commonly exposed sensitive files
func (s *Scanner) checkExposedFiles(ctx context.Context, domain string, client *http.Client, result *types.CheckResult) {
	files := map[string]string{
		"/.env":                     "Environment configuration file",
		"/.git/config":              "Git configuration file",
		"/robots.txt":               "Robots.txt file",
		"/sitemap.xml":              "XML sitemap",
		"/.well-known/security.txt": "Security policy file",
		"/wp-config.php":            "WordPress configuration",
		"/config.php":               "PHP configuration file",
		"/phpmyadmin":               "phpMyAdmin interface",
		"/admin":                    "Admin interface",
		"/backup":                   "Backup directory",
	}

	for path, description := range files {
		url := fmt.Sprintf("https://%s%s", domain, path)
		req, _ := http.NewRequestWithContext(ctx, "HEAD", url, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Sleuth/1.0)")

		if resp, err := client.Do(req); err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == 200 {
				severity := "info"
				if strings.Contains(path, ".env") || strings.Contains(path, ".git") ||
					strings.Contains(path, "config") {
					severity = "high"
				}

				result.Findings = append(result.Findings, types.Finding{
					Severity:    severity,
					Type:        "exposed_file",
					Description: fmt.Sprintf("Exposed %s", description),
					Details:     fmt.Sprintf("Accessible at %s", url),
				})
			}
		}
	}
}
