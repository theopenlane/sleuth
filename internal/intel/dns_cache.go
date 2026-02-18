package intel

import (
	"context"
	"net"
	"sync"
	"time"
)

// dnsCache provides a concurrency-safe TTL cache for DNS lookup results
type dnsCache struct {
	// mu guards concurrent access to the cache data
	mu sync.RWMutex
	// ttl is the time-to-live for cached DNS entries
	ttl time.Duration
	// data maps domain names to their cached DNS lookup results
	data map[string]dnsCacheEntry
}

// dnsCacheEntry holds the cached result and expiry for a single domain lookup
type dnsCacheEntry struct {
	// ips holds the resolved IP addresses from the DNS lookup
	ips []net.IP
	// err holds any error returned by the DNS lookup
	err error
	// expires is the time at which this cache entry becomes stale
	expires time.Time
}

// defaultCacheTTL is the fallback TTL used when a non-positive value is supplied
const defaultCacheTTL = 5 * time.Minute

// defaultLookupTimeout is the fallback timeout used for DNS resolution
const defaultLookupTimeout = 10 * time.Second

// newDNSCache creates a new DNS cache with the given TTL, falling back to a default if non-positive
func newDNSCache(ttl time.Duration) *dnsCache {
	if ttl <= 0 {
		ttl = defaultCacheTTL
	}
	return &dnsCache{
		ttl:  ttl,
		data: make(map[string]dnsCacheEntry),
	}
}

// lookup resolves a domain using the cache, performing a fresh DNS query when the entry is missing or expired
func (c *dnsCache) lookup(ctx context.Context, resolver *net.Resolver, domain string, timeout time.Duration) ([]net.IP, error) {
	now := time.Now()
	c.mu.RLock()
	entry, ok := c.data[domain]
	c.mu.RUnlock()
	if ok && entry.expires.After(now) {
		return cloneIPs(entry.ips), entry.err
	}

	if timeout <= 0 {
		timeout = defaultLookupTimeout
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

// resolveDomain performs a DNS lookup for the given domain and returns the resolved IP addresses
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

// cloneIPs returns a deep copy of the provided IP slice to prevent mutation of cached data
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
