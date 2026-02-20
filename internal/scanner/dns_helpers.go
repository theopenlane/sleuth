package scanner

import "context"

func (s *Scanner) withDNSTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if s.options == nil || s.options.DNSTimeout <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, s.options.DNSTimeout)
}
