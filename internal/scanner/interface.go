package scanner

import (
	"context"

	"github.com/theopenlane/sleuth/internal/types"
)

// Interface defines the contract for domain scanning implementations
type Interface interface {
	ScanDomain(ctx context.Context, domain string) (*types.ScanResult, error)
	Close() error
}
