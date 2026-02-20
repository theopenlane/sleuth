package scanner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
)

const takeoverBodyReadLimit = 120 * 1024

func (s *Scanner) takeoverFingerprintForCNAME(cname string) (TakeoverFingerprint, bool) {
	normalized := strings.ToLower(strings.TrimSuffix(cname, "."))
	for _, fingerprint := range takeoverFingerprints {
		if !fingerprint.Vulnerable {
			continue
		}

		if strings.HasSuffix(normalized, strings.ToLower(fingerprint.CNAMEPattern)) {
			return fingerprint, true
		}
	}

	return TakeoverFingerprint{}, false
}

func isNXDomainError(err error) bool {
	if err == nil {
		return false
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return true
	}

	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "no such host") || strings.Contains(lower, "nxdomain")
}

func (s *Scanner) confirmSubdomainTakeover(
	ctx context.Context,
	host string,
	cname string,
	fingerprint TakeoverFingerprint,
) (bool, string) {
	resolver := net.DefaultResolver
	dnsCtx, cancel := s.withDNSTimeout(ctx)
	defer cancel()

	if fingerprint.NXDomain {
		if _, err := resolver.LookupHost(dnsCtx, cname); err != nil && isNXDomainError(err) {
			return true, fmt.Sprintf("%s target %s resolved as NXDOMAIN", fingerprint.Service, cname)
		}
		return false, ""
	}

	if len(fingerprint.Fingerprints) == 0 {
		return false, ""
	}

	body, status, err := s.fetchHostBody(ctx, host)
	if err != nil {
		return false, ""
	}

	bodyLower := strings.ToLower(body)
	for _, marker := range fingerprint.Fingerprints {
		markerLower := strings.ToLower(marker)
		if markerLower == "" {
			continue
		}
		if strings.Contains(bodyLower, markerLower) {
			return true, fmt.Sprintf(
				"matched %s fingerprint marker on %s response (status=%d)",
				fingerprint.Service,
				host,
				status,
			)
		}
	}

	return false, ""
}

func (s *Scanner) fetchHostBody(ctx context.Context, host string) (string, int, error) {
	client := &http.Client{
		Timeout: s.options.HTTPTimeout,
	}

	protocols := []string{"https", "http"}
	for _, protocol := range protocols {
		target := fmt.Sprintf("%s://%s", protocol, host)

		attempts := s.options.HTTPRetries + 1
		if attempts < 1 {
			attempts = 1
		}

		for attempt := 0; attempt < attempts; attempt++ {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
			if err != nil {
				break
			}
			req.Header.Set("User-Agent", "Sleuth-Scanner/1.0")

			resp, err := client.Do(req)
			if err != nil {
				if ctx.Err() != nil {
					return "", 0, ctx.Err()
				}
				continue
			}

			bodyBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, takeoverBodyReadLimit))
			_ = resp.Body.Close()
			if readErr != nil {
				continue
			}

			return string(bodyBytes), resp.StatusCode, nil
		}
	}

	return "", 0, ErrFetchResponseBody
}
