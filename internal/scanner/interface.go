package scanner

import (
	"context"
	
	"github.com/theopenlane/sleuth/internal/types"
)

// ScannerInterface defines the interface for domain scanning
type ScannerInterface interface {
	ScanDomain(ctx context.Context, domain string) (*types.ScanResult, error)
	Close() error
}