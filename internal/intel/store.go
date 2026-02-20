package intel

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/samber/lo"
)

// indicatorStore holds all ingested threat indicators indexed by type for fast lookup
type indicatorStore struct {
	// mu guards concurrent access to store maps during hydration.
	mu sync.RWMutex
	// ip maps IP address strings to their indicator records for exact-match lookups
	ip map[string]*indicatorRecord
	// cidr holds CIDR network records for range-based IP matching
	cidr []*cidrRecord
	// domain maps domain name strings to their indicator records
	domain map[string]*indicatorRecord
	// email maps email address strings to their indicator records
	email map[string]*indicatorRecord
	// total tracks the cumulative number of indicators added to the store
	total int
}

// indicatorRecord tracks a single indicator value along with its associated categories and feeds
type indicatorRecord struct {
	// value is the normalized indicator string
	value string
	// typ is the classification of this indicator
	typ IndicatorType
	// categories holds the set of threat categories associated with this indicator
	categories map[string]struct{}
	// feeds holds the set of feed names that contributed this indicator
	feeds map[string]struct{}
}

// cidrRecord pairs a parsed CIDR network with its indicator record for range-based IP matching
type cidrRecord struct {
	// network is the parsed CIDR network used for IP containment checks
	network *net.IPNet
	// record is the indicator metadata associated with this CIDR range
	record *indicatorRecord
}

// newIndicatorStore creates an empty indicator store with initialized maps
func newIndicatorStore() *indicatorStore {
	return &indicatorStore{
		ip:     make(map[string]*indicatorRecord),
		domain: make(map[string]*indicatorRecord),
		email:  make(map[string]*indicatorRecord),
	}
}

// addIndicator inserts or merges an indicator into the store, returning true if it was accepted
func (s *indicatorStore) addIndicator(value string, typ IndicatorType, feed Feed) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if value == "" {
		return false
	}

	if !feed.AllowsIndicatorType(typ) {
		return false
	}

	catSet := make(map[string]struct{}, len(feed.Type))
	for _, c := range feed.Type {
		c = strings.TrimSpace(strings.ToLower(c))
		if c == "" {
			continue
		}
		catSet[c] = struct{}{}
	}

	var rec *indicatorRecord
	switch typ {
	case IndicatorTypeIP:
		rec = s.ensureRecord(s.ip, value, typ)
	case IndicatorTypeDomain:
		rec = s.ensureRecord(s.domain, strings.ToLower(value), typ)
	case IndicatorTypeEmail:
		rec = s.ensureRecord(s.email, strings.ToLower(value), typ)
	case IndicatorTypeCIDR:
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			return false
		}
		rec = &indicatorRecord{
			value:      network.String(),
			typ:        IndicatorTypeCIDR,
			categories: make(map[string]struct{}),
			feeds:      make(map[string]struct{}),
		}
		s.cidr = append(s.cidr, &cidrRecord{
			network: network,
			record:  rec,
		})
	default:
		return false
	}

	for c := range catSet {
		rec.categories[c] = struct{}{}
	}
	rec.feeds = rec.feedsOrInit()
	rec.feeds[feed.Name] = struct{}{}
	s.total++

	return true
}

// ensureRecord returns an existing record for the key or creates and inserts a new one
func (s *indicatorStore) ensureRecord(m map[string]*indicatorRecord, key string, typ IndicatorType) *indicatorRecord {
	if existing, ok := m[key]; ok {
		return existing
	}
	rec := &indicatorRecord{
		value:      key,
		typ:        typ,
		categories: make(map[string]struct{}),
		feeds:      make(map[string]struct{}),
	}
	m[key] = rec

	return rec
}

// feedsOrInit lazily initializes and returns the feeds map for the record
func (r *indicatorRecord) feedsOrInit() map[string]struct{} {
	if r.feeds == nil {
		r.feeds = make(map[string]struct{})
	}
	return r.feeds
}

// ingestFile reads a feed file line by line, parses indicators, and adds them to the store
func (s *indicatorStore) ingestFile(path string, feed Feed) (int, error) {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return 0, err
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	// Increase buffer to handle long lines (e.g., CSV rows)
	const maxCapacity = 2 * 1024 * 1024
	const initialBufCapacity = 64 * 1024
	buf := make([]byte, 0, initialBufCapacity)
	scanner.Buffer(buf, maxCapacity)

	var added int
	for scanner.Scan() {
		line := scanner.Text()
		value, typ := parseIndicator(line)
		if value == "" {
			continue
		}
		if s.addIndicator(value, typ, feed) {
			added++
		}
	}

	if err := scanner.Err(); err != nil {
		return added, fmt.Errorf("scan %s: %w", path, err)
	}

	return added, nil
}

// matchIP returns all indicator matches for the given IP, including exact and CIDR range hits
func (s *indicatorStore) matchIP(ip net.IP) []IndicatorMatch {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if ip == nil {
		return nil
	}
	var matches []IndicatorMatch

	if rec, ok := s.ip[ip.String()]; ok {
		matches = append(matches, recordToMatch(rec))
	}
	for _, cidr := range s.cidr {
		if cidr.network.Contains(ip) {
			matches = append(matches, recordToMatch(cidr.record))
		}
	}
	return matches
}

// matchDomain returns an indicator match if the domain exists in the store
func (s *indicatorStore) matchDomain(domain string) []IndicatorMatch {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if domain == "" {
		return nil
	}
	if rec, ok := s.domain[strings.ToLower(domain)]; ok {
		return []IndicatorMatch{recordToMatch(rec)}
	}
	return nil
}

// matchEmail returns an indicator match if the email exists in the store
func (s *indicatorStore) matchEmail(email string) []IndicatorMatch {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if email == "" {
		return nil
	}
	if rec, ok := s.email[strings.ToLower(email)]; ok {
		return []IndicatorMatch{recordToMatch(rec)}
	}
	return nil
}

// indicatorCount returns the number of indicators stored.
func (s *indicatorStore) indicatorCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.total
}

// recordToMatch converts an indicatorRecord into an IndicatorMatch for external consumption
func recordToMatch(rec *indicatorRecord) IndicatorMatch {
	return IndicatorMatch{
		Value:      rec.value,
		Type:       rec.typ,
		Categories: lo.Keys(rec.categories),
		Feeds:      lo.Keys(rec.feeds),
	}
}
