package scanner

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/theopenlane/sleuth/internal/domain"
	"github.com/theopenlane/sleuth/internal/types"
)

const (
	// orderDNSAnalysis is the display order for DNS analysis results.
	orderDNSAnalysis = 0
	// orderSubdomainDiscovery is the display order for subdomain discovery results.
	orderSubdomainDiscovery = 1
	// orderHTTPAnalysis is the display order for HTTP analysis results.
	orderHTTPAnalysis = 2
	// orderTechnologyDetection is the display order for technology detection results.
	orderTechnologyDetection = 3
	// orderNucleiScan is the display order for nuclei scan results.
	orderNucleiScan = 4
)

var checkResultOrder = map[string]int{
	"dns_analysis":         orderDNSAnalysis,
	"subdomain_discovery":  orderSubdomainDiscovery,
	"http_analysis":        orderHTTPAnalysis,
	"technology_detection": orderTechnologyDetection,
	"nuclei_scan":          orderNucleiScan,
}

// Scanner performs comprehensive domain analysis.
type Scanner struct {
	// options holds the configuration for scan behavior.
	options *ScanOptions
}

// New creates a new scanner with the given options.
func New(opts ...ScanOption) (*Scanner, error) {
	options := DefaultScanOptions()
	for _, opt := range opts {
		opt(options)
	}

	return &Scanner{
		options: options,
	}, nil
}

// ScanDomain performs comprehensive domain analysis.
func (s *Scanner) ScanDomain(ctx context.Context, domainName string) (*types.ScanResult, error) {
	info, err := domain.Parse(domainName)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidDomain, err)
	}

	result := &types.ScanResult{
		Domain:    info.Domain,
		ScannedAt: fmt.Sprintf("%d", time.Now().Unix()),
		DomainInfo: &types.DomainInfo{
			Domain:    info.Domain,
			Subdomain: info.Subdomain,
			TLD:       info.TLD,
			SLD:       info.SLD,
		},
		Results: make([]types.CheckResult, 0),
	}

	// resultBufSize is the buffer size for the scan results channel.
	const resultBufSize = 10

	resultsChan := make(chan types.CheckResult, resultBufSize)
	var wg sync.WaitGroup

	wg.Go(func() {
		if dnsResult := s.performDNSAnalysis(ctx, info.Domain); dnsResult != nil {
			resultsChan <- *dnsResult
		}
	})
	wg.Go(func() {
		if subResult := s.performSubdomainDiscovery(ctx, info.Domain); subResult != nil {
			resultsChan <- *subResult
		}
	})
	wg.Go(func() {
		if httpResult := s.performHTTPAnalysis(ctx, info.Domain); httpResult != nil {
			resultsChan <- *httpResult
		}
	})
	wg.Go(func() {
		if techResult := s.performTechnologyDetection(ctx, info.Domain); techResult != nil {
			resultsChan <- *techResult
		}
	})

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	for checkResult := range resultsChan {
		result.Results = append(result.Results, checkResult)
	}

	if len(s.options.NucleiTemplates) > 0 {
		if nucleiResult := s.performNucleiScan(ctx, info.Domain); nucleiResult != nil {
			result.Results = append(result.Results, *nucleiResult)
		}
	}

	sort.SliceStable(result.Results, func(i, j int) bool {
		iOrder, iOk := checkResultOrder[result.Results[i].CheckName]
		jOrder, jOk := checkResultOrder[result.Results[j].CheckName]
		switch {
		case iOk && jOk:
			return iOrder < jOrder
		case iOk:
			return true
		case jOk:
			return false
		default:
			return result.Results[i].CheckName < result.Results[j].CheckName
		}
	})

	return result, nil
}

// Close cleans up scanner resources.
func (s *Scanner) Close() error {
	return nil
}
