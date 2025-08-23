package scanner

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/theopenlane/sleuth/internal/types"
)

// performTechnologyDetection identifies technologies used by the domain
func (s *Scanner) performTechnologyDetection(ctx context.Context, domain string) *types.CheckResult {
	result := &types.CheckResult{
		CheckName: "technology_detection",
		Status:    "pass",
		Findings:  []types.Finding{},
		Metadata:  make(map[string]interface{}),
	}

	// This method focuses on DNS-based technology detection
	// HTTP-based detection is handled in performHTTPAnalysis
	
	// Check for CDN via DNS
	s.detectCDNFromDNS(domain, result)
	
	// Check for hosting provider via IP ranges
	s.detectHostingProvider(domain, result)
	
	// Check for cloud services
	s.detectCloudServices(domain, result)

	return result
}

// detectTechnologies identifies technologies from HTTP headers and body content
func (s *Scanner) detectTechnologies(body string, headers http.Header, result *types.CheckResult) {
	technologies := make(map[string]string)

	// Server header analysis
	if server := headers.Get("Server"); server != "" {
		technologies["server"] = server
		s.analyzeServerHeader(server, result)
	}

	// X-Powered-By header
	if poweredBy := headers.Get("X-Powered-By"); poweredBy != "" {
		technologies["powered_by"] = poweredBy
		s.analyzePoweredByHeader(poweredBy, result)
	}

	// CDN/Proxy detection from headers
	s.detectCDNFromHeaders(headers, result)

	// Framework detection from headers
	s.detectFrameworksFromHeaders(headers, result)

	// Content-based detection
	s.detectTechnologiesFromContent(body, result)

	result.Metadata["detected_technologies"] = technologies
}

// analyzeServerHeader analyzes the Server header for technology information
func (s *Scanner) analyzeServerHeader(server string, result *types.CheckResult) {
	serverLower := strings.ToLower(server)
	
	serverMappings := map[string]string{
		"nginx":           "Nginx",
		"apache":          "Apache HTTP Server",
		"microsoft-iis":   "Microsoft IIS",
		"cloudflare":      "Cloudflare",
		"amazon-cloudfront": "Amazon CloudFront",
		"openresty":       "OpenResty",
		"litespeed":       "LiteSpeed",
		"caddy":           "Caddy",
	}

	for pattern, name := range serverMappings {
		if strings.Contains(serverLower, pattern) {
			result.Findings = append(result.Findings, types.Finding{
				Severity:    "info",
				Type:        "technology",
				Description: fmt.Sprintf("Web Server: %s", name),
				Details:     fmt.Sprintf("Server header: %s", server),
			})
			break
		}
	}
}

// analyzePoweredByHeader analyzes the X-Powered-By header
func (s *Scanner) analyzePoweredByHeader(poweredBy string, result *types.CheckResult) {
	poweredByLower := strings.ToLower(poweredBy)
	
	if strings.Contains(poweredByLower, "php") {
		result.Findings = append(result.Findings, types.Finding{
			Severity:    "info",
			Type:        "technology",
			Description: "Language: PHP",
			Details:     fmt.Sprintf("X-Powered-By: %s", poweredBy),
		})
	} else if strings.Contains(poweredByLower, "asp.net") {
		result.Findings = append(result.Findings, types.Finding{
			Severity:    "info",
			Type:        "technology", 
			Description: "Framework: ASP.NET",
			Details:     fmt.Sprintf("X-Powered-By: %s", poweredBy),
		})
	} else if strings.Contains(poweredByLower, "express") {
		result.Findings = append(result.Findings, types.Finding{
			Severity:    "info",
			Type:        "technology",
			Description: "Framework: Express.js",
			Details:     fmt.Sprintf("X-Powered-By: %s", poweredBy),
		})
	}
}

// detectCDNFromHeaders detects CDN usage from HTTP headers
func (s *Scanner) detectCDNFromHeaders(headers http.Header, result *types.CheckResult) {
	cdnHeaders := map[string]string{
		"CF-Ray":                   "Cloudflare",
		"X-Amz-Cf-Id":              "Amazon CloudFront",
		"X-Akamai-Transformed":     "Akamai",
		"X-Fastly-Request-ID":      "Fastly",
		"X-Served-By":              "Fastly/Varnish",
		"X-Cache":                  "Various CDN",
		"X-Azure-Ref":              "Azure CDN",
		"X-Edge-Location":          "AWS CloudFront",
		"X-Cdn":                    "Generic CDN",
	}

	for header, cdn := range cdnHeaders {
		if value := headers.Get(header); value != "" {
			result.Findings = append(result.Findings, types.Finding{
				Severity:    "info",
				Type:        "technology",
				Description: fmt.Sprintf("CDN: %s", cdn),
				Details:     fmt.Sprintf("Header: %s = %s", header, value),
			})
		}
	}
}

// detectFrameworksFromHeaders detects web frameworks from headers
func (s *Scanner) detectFrameworksFromHeaders(headers http.Header, result *types.CheckResult) {
	// Check for framework-specific headers
	if headers.Get("X-Drupal-Cache") != "" {
		result.Findings = append(result.Findings, types.Finding{
			Severity:    "info",
			Type:        "technology",
			Description: "CMS: Drupal",
			Details:     "X-Drupal-Cache header present",
		})
	}

	if headers.Get("X-Pingback") != "" {
		result.Findings = append(result.Findings, types.Finding{
			Severity:    "info",
			Type:        "technology",
			Description: "CMS: WordPress",
			Details:     "X-Pingback header present",
		})
	}
}

// detectTechnologiesFromContent analyzes HTML content for technology signatures
func (s *Scanner) detectTechnologiesFromContent(body string, result *types.CheckResult) {
	bodyLower := strings.ToLower(body)

	// CMS Detection
	cmsPatterns := map[string]string{
		"wp-content":       "WordPress",
		"wp-includes":      "WordPress",
		"/joomla":          "Joomla",
		"drupal":           "Drupal",
		"typo3":            "TYPO3",
		"magento":          "Magento",
		"shopify":          "Shopify",
		"prestashop":       "PrestaShop",
		"wix.com":          "Wix",
		"squarespace":      "Squarespace",
		"ghost":            "Ghost",
		"craft cms":        "Craft CMS",
	}

	for pattern, cms := range cmsPatterns {
		if strings.Contains(bodyLower, pattern) {
			result.Findings = append(result.Findings, types.Finding{
				Severity:    "info",
				Type:        "technology",
				Description: fmt.Sprintf("CMS: %s", cms),
				Details:     fmt.Sprintf("Pattern '%s' found in HTML", pattern),
			})
		}
	}

	// JavaScript frameworks/libraries
	jsPatterns := map[string]string{
		"react":            "React",
		"vue.js":           "Vue.js",
		"angular":          "Angular",
		"jquery":           "jQuery",
		"bootstrap":        "Bootstrap",
		"tailwind":         "Tailwind CSS",
		"next.js":          "Next.js",
		"gatsby":           "Gatsby",
		"_next/static":     "Next.js",
		"nuxt":             "Nuxt.js",
		"ember":            "Ember.js",
		"backbone":         "Backbone.js",
	}

	for pattern, tech := range jsPatterns {
		if strings.Contains(bodyLower, pattern) {
			result.Findings = append(result.Findings, types.Finding{
				Severity:    "info",
				Type:        "technology",
				Description: fmt.Sprintf("JavaScript Framework: %s", tech),
				Details:     fmt.Sprintf("Pattern '%s' found in HTML", pattern),
			})
		}
	}

	// Analytics and tracking
	analyticsPatterns := map[string]string{
		"google-analytics.com":     "Google Analytics",
		"googletagmanager.com":     "Google Tag Manager",
		"facebook.com/tr":          "Facebook Pixel",
		"matomo":                   "Matomo",
		"hotjar":                   "Hotjar",
		"segment.com":              "Segment",
		"mixpanel":                 "Mixpanel",
		"amplitude":                "Amplitude",
		"intercom":                 "Intercom",
	}

	for pattern, analytics := range analyticsPatterns {
		if strings.Contains(bodyLower, pattern) {
			result.Findings = append(result.Findings, types.Finding{
				Severity:    "info",
				Type:        "technology",
				Description: fmt.Sprintf("Analytics: %s", analytics),
				Details:     fmt.Sprintf("Pattern '%s' found in HTML", pattern),
			})
		}
	}
}

// detectCDNFromDNS detects CDN usage from DNS records
func (s *Scanner) detectCDNFromDNS(domain string, result *types.CheckResult) {
	// Check CNAME records for CDN patterns
	if cname, err := net.LookupCNAME(domain); err == nil && cname != domain+"." {
		cnameClean := strings.TrimSuffix(cname, ".")
		
		cdnPatterns := map[string]string{
			"cloudfront.net":       "Amazon CloudFront",
			"cloudflare.com":       "Cloudflare",
			"fastly.com":           "Fastly",
			"akamai.net":           "Akamai",
			"azureedge.net":        "Azure CDN",
			"googleusercontent.com": "Google Cloud CDN",
			"jsdelivr.net":         "jsDelivr CDN",
			"maxcdn.com":           "MaxCDN",
		}

		for pattern, cdn := range cdnPatterns {
			if strings.Contains(strings.ToLower(cnameClean), pattern) {
				result.Findings = append(result.Findings, types.Finding{
					Severity:    "info",
					Type:        "technology",
					Description: fmt.Sprintf("CDN: %s", cdn),
					Details:     fmt.Sprintf("CNAME points to %s", cnameClean),
				})
			}
		}
	}
}

// detectHostingProvider detects hosting provider from IP ranges
func (s *Scanner) detectHostingProvider(domain string, result *types.CheckResult) {
	if ips, err := net.LookupIP(domain); err == nil && len(ips) > 0 {
		for _, ip := range ips {
			if ip.To4() == nil {
				continue // Skip IPv6 for now
			}
			ipStr := ip.String()
			
			// AWS IP ranges (simplified)
			awsPrefixes := []string{
				"52.", "54.", "18.", "35.", "13.", "34.", "3.", "15.", 
				"16.", "17.", "23.", "50.", "52.", "75.", "99.",
			}
			
			// Google Cloud IP ranges (simplified)
			gcpPrefixes := []string{
				"35.", "34.", "104.", "130.", "146.", "172.", "173.",
			}
			
			// Azure IP ranges (simplified)
			azurePrefixes := []string{
				"13.", "20.", "23.", "40.", "51.", "52.", "65.", "104.",
				"137.", "138.", "168.",
			}
			
			for _, prefix := range awsPrefixes {
				if strings.HasPrefix(ipStr, prefix) {
					result.Findings = append(result.Findings, types.Finding{
						Severity:    "info",
						Type:        "technology",
						Description: "Hosting: Amazon Web Services",
						Details:     fmt.Sprintf("IP: %s", ipStr),
					})
					return
				}
			}
			
			for _, prefix := range gcpPrefixes {
				if strings.HasPrefix(ipStr, prefix) {
					result.Findings = append(result.Findings, types.Finding{
						Severity:    "info",
						Type:        "technology",
						Description: "Hosting: Google Cloud Platform",
						Details:     fmt.Sprintf("IP: %s", ipStr),
					})
					return
				}
			}
			
			for _, prefix := range azurePrefixes {
				if strings.HasPrefix(ipStr, prefix) {
					result.Findings = append(result.Findings, types.Finding{
						Severity:    "info",
						Type:        "technology",
						Description: "Hosting: Microsoft Azure",
						Details:     fmt.Sprintf("IP: %s", ipStr),
					})
					return
				}
			}
		}
	}
}

// detectCloudServices detects cloud services from DNS patterns
func (s *Scanner) detectCloudServices(domain string, result *types.CheckResult) {
	// Check for common cloud service patterns in CNAME records
	if cname, err := net.LookupCNAME(domain); err == nil && cname != domain+"." {
		cnameClean := strings.TrimSuffix(cname, ".")
		
		cloudPatterns := map[string]string{
			"amazonaws.com":        "Amazon Web Services",
			"googleusercontent.com": "Google Cloud",
			"azurewebsites.net":    "Azure App Service",
			"herokuapp.com":        "Heroku",
			"netlify.com":          "Netlify",
			"vercel.com":           "Vercel",
			"github.io":            "GitHub Pages",
			"gitlab.io":            "GitLab Pages",
		}

		for pattern, service := range cloudPatterns {
			if strings.Contains(strings.ToLower(cnameClean), pattern) {
				result.Findings = append(result.Findings, types.Finding{
					Severity:    "info",
					Type:        "technology",
					Description: fmt.Sprintf("Cloud Service: %s", service),
					Details:     fmt.Sprintf("CNAME points to %s", cnameClean),
				})
			}
		}
	}
}