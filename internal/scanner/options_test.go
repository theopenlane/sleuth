package scanner

import (
	"testing"
	"time"
)

func TestDefaultScanOptions(t *testing.T) {
	opts := DefaultScanOptions()
	
	if opts.DNSTimeout != 10*time.Second {
		t.Errorf("Expected DNS timeout to be 10s, got %v", opts.DNSTimeout)
	}
	
	if len(opts.DNSResolvers) != 2 {
		t.Errorf("Expected 2 default DNS resolvers, got %d", len(opts.DNSResolvers))
	}
	
	if opts.MaxSubdomains != 100 {
		t.Errorf("Expected max subdomains to be 100, got %d", opts.MaxSubdomains)
	}
	
	if !opts.Silent {
		t.Error("Expected silent mode to be true by default")
	}
	
	if opts.Verbose {
		t.Error("Expected verbose mode to be false by default")
	}
}

func TestScanOptions_WithDNSTimeout(t *testing.T) {
	opts := DefaultScanOptions()
	timeout := 30 * time.Second
	
	WithDNSTimeout(timeout)(opts)
	
	if opts.DNSTimeout != timeout {
		t.Errorf("Expected DNS timeout to be %v, got %v", timeout, opts.DNSTimeout)
	}
}

func TestScanOptions_WithDNSResolvers(t *testing.T) {
	opts := DefaultScanOptions()
	resolvers := []string{"1.1.1.1", "9.9.9.9"}
	
	WithDNSResolvers(resolvers)(opts)
	
	if len(opts.DNSResolvers) != 2 {
		t.Errorf("Expected 2 DNS resolvers, got %d", len(opts.DNSResolvers))
	}
	
	if opts.DNSResolvers[0] != "1.1.1.1" {
		t.Errorf("Expected first resolver to be 1.1.1.1, got %s", opts.DNSResolvers[0])
	}
}

func TestScanOptions_WithMaxSubdomains(t *testing.T) {
	opts := DefaultScanOptions()
	max := 50
	
	WithMaxSubdomains(max)(opts)
	
	if opts.MaxSubdomains != max {
		t.Errorf("Expected max subdomains to be %d, got %d", max, opts.MaxSubdomains)
	}
}

func TestScanOptions_WithVerbose(t *testing.T) {
	opts := DefaultScanOptions()
	
	WithVerbose(true)(opts)
	
	if !opts.Verbose {
		t.Error("Expected verbose mode to be true")
	}
}

func TestScanOptions_WithNucleiTemplates(t *testing.T) {
	opts := DefaultScanOptions()
	templates := []string{"cves", "exposures"}
	
	WithNucleiTemplates(templates)(opts)
	
	if len(opts.NucleiTemplates) != 2 {
		t.Errorf("Expected 2 nuclei templates, got %d", len(opts.NucleiTemplates))
	}
	
	if opts.NucleiTemplates[0] != "cves" {
		t.Errorf("Expected first template to be 'cves', got %s", opts.NucleiTemplates[0])
	}
}

func TestScanOptions_WithNucleiSeverity(t *testing.T) {
	opts := DefaultScanOptions()
	severity := []string{"critical", "high"}
	
	WithNucleiSeverity(severity)(opts)
	
	if len(opts.NucleiSeverity) != 2 {
		t.Errorf("Expected 2 nuclei severity levels, got %d", len(opts.NucleiSeverity))
	}
	
	if opts.NucleiSeverity[0] != "critical" {
		t.Errorf("Expected first severity to be 'critical', got %s", opts.NucleiSeverity[0])
	}
}

func TestScanOptions_ChainedOptions(t *testing.T) {
	opts := DefaultScanOptions()
	
	WithDNSTimeout(15*time.Second)(opts)
	WithMaxSubdomains(200)(opts)
	WithVerbose(true)(opts)
	
	if opts.DNSTimeout != 15*time.Second {
		t.Errorf("Expected DNS timeout to be 15s, got %v", opts.DNSTimeout)
	}
	
	if opts.MaxSubdomains != 200 {
		t.Errorf("Expected max subdomains to be 200, got %d", opts.MaxSubdomains)
	}
	
	if !opts.Verbose {
		t.Error("Expected verbose mode to be true")
	}
}