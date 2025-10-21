package scanner

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/theopenlane/sleuth/internal/domain"
	"github.com/theopenlane/sleuth/internal/types"
)

// Scanner performs comprehensive domain analysis
type Scanner struct {
	options    *ScanOptions
	nucleiPath string
}

// New creates a new scanner with the given options
func New(opts ...ScanOption) (*Scanner, error) {
	options := DefaultScanOptions()
	for _, opt := range opts {
		opt(options)
	}

	return &Scanner{
		options:    options,
		nucleiPath: "/usr/local/bin/nuclei", // Default path, will be configurable
	}, nil
}

// ScanDomain performs comprehensive domain analysis
func (s *Scanner) ScanDomain(ctx context.Context, domainName string) (*types.ScanResult, error) {
	// Parse domain
	info, err := domain.Parse(domainName)
	if err != nil {
		return nil, fmt.Errorf("invalid domain: %w", err)
	}

	domainInfo := &types.DomainInfo{
		Domain:    info.Domain,
		Subdomain: info.Subdomain,
		TLD:       info.TLD,
		SLD:       info.SLD,
	}

	result := &types.ScanResult{
		Domain:     info.Domain,
		ScannedAt:  fmt.Sprintf("%d", time.Now().Unix()),
		DomainInfo: domainInfo,
		Results:    make([]types.CheckResult, 0),
	}

	// Create a channel to collect results
	resultsChan := make(chan types.CheckResult, 10)
	var wg sync.WaitGroup

	// DNS Analysis
	wg.Add(1)
	go func() {
		defer wg.Done()
		if dnsResult := s.performDNSAnalysis(ctx, info.Domain); dnsResult != nil {
			resultsChan <- *dnsResult
		}
	}()

	// Subdomain Discovery
	wg.Add(1)
	go func() {
		defer wg.Done()
		if subResult := s.performSubdomainDiscovery(ctx, info.Domain); subResult != nil {
			resultsChan <- *subResult
		}
	}()

	// HTTP Analysis (after subdomain discovery)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if httpResult := s.performHTTPAnalysis(ctx, info.Domain); httpResult != nil {
			resultsChan <- *httpResult
		}
	}()

	// Technology Detection
	wg.Add(1)
	go func() {
		defer wg.Done()
		if techResult := s.performTechnologyDetection(ctx, info.Domain); techResult != nil {
			resultsChan <- *techResult
		}
	}()

	// Close results channel when all goroutines complete
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Collect results
	for checkResult := range resultsChan {
		result.Results = append(result.Results, checkResult)
	}

	// Perform Nuclei scan if enabled
	if len(s.options.NucleiTemplates) > 0 {
		if nucleiResult := s.performNucleiScan(ctx, info.Domain); nucleiResult != nil {
			result.Results = append(result.Results, *nucleiResult)
		}
	}

	return result, nil
}

// Close cleans up scanner resources
func (s *Scanner) Close() error {
	// No resources to clean up in simplified version
	return nil
}