package intel

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

type indicatorStore struct {
	ip     map[string]*indicatorRecord
	cidr   []*cidrRecord
	domain map[string]*indicatorRecord
	email  map[string]*indicatorRecord
	total  int
}

type indicatorRecord struct {
	value      string
	typ        IndicatorType
	categories map[string]struct{}
	feeds      map[string]struct{}
}

type cidrRecord struct {
	network *net.IPNet
	record  *indicatorRecord
}

func newIndicatorStore() *indicatorStore {
	return &indicatorStore{
		ip:     make(map[string]*indicatorRecord),
		domain: make(map[string]*indicatorRecord),
		email:  make(map[string]*indicatorRecord),
	}
}

func (s *indicatorStore) addIndicator(value string, typ IndicatorType, feed Feed) bool {
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

func (r *indicatorRecord) feedsOrInit() map[string]struct{} {
	if r.feeds == nil {
		r.feeds = make(map[string]struct{})
	}
	return r.feeds
}

func (s *indicatorStore) ingestFile(path string, feed Feed) (int, error) {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return 0, err
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	// Increase buffer to handle long lines (e.g., CSV rows)
	const maxCapacity = 2 * 1024 * 1024
	buf := make([]byte, 0, 64*1024)
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

func (s *indicatorStore) matchIP(ip net.IP) []IndicatorMatch {
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

func (s *indicatorStore) matchDomain(domain string) []IndicatorMatch {
	if domain == "" {
		return nil
	}
	if rec, ok := s.domain[strings.ToLower(domain)]; ok {
		return []IndicatorMatch{recordToMatch(rec)}
	}
	return nil
}

func (s *indicatorStore) matchEmail(email string) []IndicatorMatch {
	if email == "" {
		return nil
	}
	if rec, ok := s.email[strings.ToLower(email)]; ok {
		return []IndicatorMatch{recordToMatch(rec)}
	}
	return nil
}

func recordToMatch(rec *indicatorRecord) IndicatorMatch {
	match := IndicatorMatch{
		Value: rec.value,
		Type:  rec.typ,
	}
	for c := range rec.categories {
		match.Categories = append(match.Categories, c)
	}
	for f := range rec.feeds {
		match.Feeds = append(match.Feeds, f)
	}
	return match
}
