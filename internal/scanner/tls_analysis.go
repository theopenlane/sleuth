package scanner

import (
	"fmt"
	"strings"
	"time"

	"github.com/projectdiscovery/tlsx/pkg/tlsx"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"

	"github.com/theopenlane/sleuth/internal/types"
)

const (
	// defaultTLSTimeout is the fallback timeout in seconds for TLS connections
	defaultTLSTimeout = 10
	// tlsRetries is the number of retry attempts for TLS connections
	tlsRetries = 2
	// hoursPerDay is used to convert hours to days for certificate expiry checks
	hoursPerDay = 24
)

// analyzeTLSWithTLSX analyzes TLS/SSL configuration using tlsx library
func (s *Scanner) analyzeTLSWithTLSX(domain string, result *types.CheckResult) {
	// Create tlsx options
	timeout := int(s.options.HTTPTimeout.Seconds())
	if timeout <= 0 {
		timeout = defaultTLSTimeout
	}

	options := &clients.Options{
		Timeout:    timeout,
		Retries:    tlsRetries,
		Expired:    true,
		SelfSigned: true,
		MisMatched: true,
		Revoked:    true,
		MinVersion: "tls10",
		MaxVersion: "tls13",
	}

	// Create tlsx service
	service, err := tlsx.New(options)
	if err != nil {
		result.Findings = append(result.Findings, types.Finding{
			Severity:    "info",
			Type:        "tls_analysis_error",
			Description: fmt.Sprintf("TLS analysis initialization failed: %v", err),
		})
		return
	}

	// Scan the domain on standard HTTPS port
	response, err := service.Connect(domain, "", "443")
	if err != nil {
		result.Findings = append(result.Findings, types.Finding{
			Severity:    "info",
			Type:        "tls_connection_failed",
			Description: fmt.Sprintf("TLS connection failed: %v", err),
		})
		return
	}

	if response == nil {
		return
	}

	// Build TLS metadata
	tlsInfo := make(map[string]any)

	// TLS version analysis
	if response.Version != "" {
		tlsInfo["version"] = response.Version

		// Check for deprecated TLS versions
		versionLower := strings.ToLower(response.Version)
		if strings.Contains(versionLower, "tls10") || strings.Contains(versionLower, "1.0") {
			result.Findings = append(result.Findings, types.Finding{
				Severity:    "critical",
				Type:        "weak_tls",
				Description: "Outdated TLS 1.0 in use",
				Details:     "TLS 1.0 is deprecated and has known vulnerabilities",
			})
		} else if strings.Contains(versionLower, "tls11") || strings.Contains(versionLower, "1.1") {
			result.Findings = append(result.Findings, types.Finding{
				Severity:    "high",
				Type:        "weak_tls",
				Description: "Outdated TLS 1.1 in use",
				Details:     "TLS 1.1 is deprecated and should be upgraded",
			})
		}
	}

	// Cipher suite analysis
	if response.Cipher != "" {
		tlsInfo["cipher_suite"] = response.Cipher

		// Check for weak ciphers
		cipherLower := strings.ToLower(response.Cipher)
		if strings.Contains(cipherLower, "rc4") || strings.Contains(cipherLower, "des") ||
			strings.Contains(cipherLower, "md5") || strings.Contains(cipherLower, "null") {
			result.Findings = append(result.Findings, types.Finding{
				Severity:    "critical",
				Type:        "weak_cipher",
				Description: "Weak cipher suite in use",
				Details:     fmt.Sprintf("Cipher: %s", response.Cipher),
			})
		}
	}

	// Certificate analysis
	certInfo := make(map[string]any)

	if response.SubjectDN != "" {
		certInfo["subject"] = response.SubjectDN
	}
	if response.IssuerDN != "" {
		certInfo["issuer"] = response.IssuerDN
	}
	if !response.NotBefore.IsZero() {
		certInfo["not_before"] = response.NotBefore.Format(time.RFC3339)
	}
	if !response.NotAfter.IsZero() {
		certInfo["not_after"] = response.NotAfter.Format(time.RFC3339)
	}
	if len(response.SubjectAN) > 0 {
		certInfo["dns_names"] = response.SubjectAN
	}

	// Check for expired certificate
	if response.Expired {
		result.Findings = append(result.Findings, types.Finding{
			Severity:    "critical",
			Type:        "expired_certificate",
			Description: "SSL certificate has expired",
			Details:     fmt.Sprintf("Certificate expired on %s", response.NotAfter.Format(time.RFC3339)),
		})
	}

	// Check for expiring certificate
	if !response.NotAfter.IsZero() && !response.Expired {
		daysUntilExpiry := int(time.Until(response.NotAfter).Hours() / hoursPerDay)
		if daysUntilExpiry > 0 && daysUntilExpiry < 30 {
			result.Findings = append(result.Findings, types.Finding{
				Severity:    "high",
				Type:        "expiring_certificate",
				Description: "SSL certificate expiring soon",
				Details:     fmt.Sprintf("Expires in %d days", daysUntilExpiry),
			})
		}
	}

	// Check for self-signed certificate
	if response.SelfSigned {
		result.Findings = append(result.Findings, types.Finding{
			Severity:    "high",
			Type:        "self_signed_certificate",
			Description: "Self-signed certificate detected",
			Details:     "Certificate is not issued by a trusted CA",
		})
	}

	// Check for mismatched certificate
	if response.MisMatched {
		result.Findings = append(result.Findings, types.Finding{
			Severity:    "high",
			Type:        "certificate_mismatch",
			Description: "Certificate does not match domain",
			Details:     fmt.Sprintf("Expected domain: %s", domain),
		})
	}

	// Check for revoked certificate
	if response.Revoked {
		result.Findings = append(result.Findings, types.Finding{
			Severity:    "critical",
			Type:        "revoked_certificate",
			Description: "Certificate has been revoked",
			Details:     "Certificate is listed in revocation list",
		})
	}

	tlsInfo["certificate"] = certInfo

	// Add JARM fingerprint if available
	if response.JarmHash != "" {
		tlsInfo["jarm_fingerprint"] = response.JarmHash
	}

	result.Metadata["tls"] = tlsInfo
}
