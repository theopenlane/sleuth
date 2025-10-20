package intel

import (
	"net"
	"regexp"
	"strings"
	"unicode"
)

var (
	ipv4Regex   = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`)
	ipv6Regex   = regexp.MustCompile(`(?i)\b(([0-9a-f]{1,4}:){1,7}[0-9a-f]{1,4}|(::1)|(::))\b`)
	domainRegex = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
	emailRegex  = regexp.MustCompile(`^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$`)
)

// parseIndicator attempts to extract an indicator from a raw feed line.
func parseIndicator(line string) (string, IndicatorType) {
	cleaned := sanitizeLine(line)
	if cleaned == "" {
		return "", ""
	}

	fields := splitFields(cleaned)
	if len(fields) == 0 {
		return "", ""
	}

	candidate := strings.Trim(fields[0], "\"'[]")

	if strings.Contains(candidate, "/") {
		if _, network, err := net.ParseCIDR(candidate); err == nil {
			return network.String(), IndicatorTypeCIDR
		}
	}

	if parsedIP := net.ParseIP(candidate); parsedIP != nil {
		if !isPrivateOrInvalidIP(parsedIP, candidate) {
			return parsedIP.String(), IndicatorTypeIP
		}
		return "", ""
	}

	if ip := findIPInLine(cleaned); ip != "" {
		return ip, IndicatorTypeIP
	}

	lower := strings.ToLower(candidate)
	if emailRegex.MatchString(lower) {
		return lower, IndicatorTypeEmail
	}

	if domainRegex.MatchString(lower) {
		return lower, IndicatorTypeDomain
	}

	return "", ""
}

func splitFields(input string) []string {
	return strings.FieldsFunc(input, func(r rune) bool {
		switch {
		case unicode.IsSpace(r):
			return true
		case r == ',' || r == ';' || r == '|':
			return true
		default:
			return false
		}
	})
}

func sanitizeLine(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}

	if idx := strings.Index(line, "#"); idx >= 0 {
		line = line[:idx]
	}
	if idx := strings.Index(line, ";"); idx >= 0 {
		line = line[:idx]
	}

	return strings.TrimSpace(line)
}

func findIPInLine(line string) string {
	if match := ipv4Regex.FindString(line); match != "" {
		if ip := net.ParseIP(match); ip != nil && !isPrivateOrInvalidIP(ip, match) {
			return ip.String()
		}
	}
	if match := ipv6Regex.FindString(line); match != "" {
		if ip := net.ParseIP(match); ip != nil && !isPrivateOrInvalidIP(ip, match) {
			return ip.String()
		}
	}
	return ""
}

func isPrivateOrInvalidIP(ip net.IP, value string) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast() || ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	if ip.IsPrivate() {
		return true
	}
	if value == "0.0.0.0" || strings.HasPrefix(value, "255.") {
		return true
	}
	if value == "::" || value == "::1" {
		return true
	}
	return false
}
