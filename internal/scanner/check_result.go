package scanner

import (
	"fmt"

	"github.com/theopenlane/sleuth/internal/types"
)

// newCheckResult creates a check result with normalized defaults.
func newCheckResult(name string) *types.CheckResult {
	return &types.CheckResult{
		CheckName: name,
		Status:    types.CheckStatusPass,
		Findings:  make([]types.Finding, 0),
		Metadata:  make(map[string]any),
	}
}

// markCheckError marks a check as error with a formatted message.
func markCheckError(result *types.CheckResult, format string, args ...any) {
	result.Status = types.CheckStatusError
	result.Error = fmt.Sprintf(format, args...)
}

// markCheckFailed marks a check as failed unless it is already in an error or timeout state.
func markCheckFailed(result *types.CheckResult) {
	switch result.Status {
	case types.CheckStatusError, types.CheckStatusTimeout:
		return
	default:
		result.Status = types.CheckStatusFail
	}
}
