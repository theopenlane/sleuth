package intel

import (
	"context"
	"net"
	"sync"
	"time"
)

type dnsCache struct {
	mu   sync.RWMutex
	ttl  time.Duration
	data map[string]dnsCacheEntry
}

type dnsCacheEntry struct {
	ips     []net.IP
	err     error
	expires time.Time
}

func newDNSCache(ttl time.Duration) *dnsCache {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &dnsCache{
		ttl:  ttl,
		data: make(map[string]dnsCacheEntry),
	}
}

func (c *dnsCache) lookup(ctx context.Context, resolver *net.Resolver, domain string, timeout time.Duration) ([]net.IP, error) {
	now := time.Now()
	c.mu.RLock()
	entry, ok := c.data[domain]
	c.mu.RUnlock()
	if ok && entry.expires.After(now) {
		return cloneIPs(entry.ips), entry.err
	}

	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	resolverCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ips, err := resolveDomain(resolverCtx, resolver, domain)

	c.mu.Lock()
	c.data[domain] = dnsCacheEntry{
		ips:     cloneIPs(ips),
		err:     err,
		expires: now.Add(c.ttl),
	}
	c.mu.Unlock()

	return ips, err
}

func resolveDomain(ctx context.Context, resolver *net.Resolver, domain string) ([]net.IP, error) {
	res := resolver
	if res == nil {
		res = net.DefaultResolver
	}
	addrs, err := res.LookupIPAddr(ctx, domain)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		if addr.IP != nil {
			ipCopy := make(net.IP, len(addr.IP))
			copy(ipCopy, addr.IP)
			ips = append(ips, ipCopy)
		}
	}
	return ips, nil
}

func cloneIPs(src []net.IP) []net.IP {
	if len(src) == 0 {
		return nil
	}
	dst := make([]net.IP, 0, len(src))
	for _, ip := range src {
		if ip == nil {
			continue
		}
		copyIP := make(net.IP, len(ip))
		copy(copyIP, ip)
		dst = append(dst, copyIP)
	}
	return dst
}
