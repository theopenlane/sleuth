package config

import (
	"os"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	cfg := New()

	if cfg.Port != "8080" {
		t.Errorf("expected default port 8080, got %s", cfg.Port)
	}
	if cfg.ReadTimeout != 30*time.Second {
		t.Errorf("expected default read timeout 30s, got %v", cfg.ReadTimeout)
	}
	if cfg.WriteTimeout != 180*time.Second {
		t.Errorf("expected default write timeout 180s, got %v", cfg.WriteTimeout)
	}
	if cfg.ShutdownTimeout != 30*time.Second {
		t.Errorf("expected default shutdown timeout 30s, got %v", cfg.ShutdownTimeout)
	}
	if cfg.ScanTimeout != 120*time.Second {
		t.Errorf("expected default scan timeout 120s, got %v", cfg.ScanTimeout)
	}
	if cfg.MaxBodySize != 100*1024 {
		t.Errorf("expected default max body size 102400, got %d", cfg.MaxBodySize)
	}
}

func TestNewWithEnvVars(t *testing.T) {
	originalEnv := map[string]string{
		"SLEUTH_PORT":                   os.Getenv("SLEUTH_PORT"),
		"SLEUTH_READ_TIMEOUT":           os.Getenv("SLEUTH_READ_TIMEOUT"),
		"SLEUTH_WRITE_TIMEOUT":          os.Getenv("SLEUTH_WRITE_TIMEOUT"),
		"SLEUTH_SHUTDOWN_TIMEOUT":       os.Getenv("SLEUTH_SHUTDOWN_TIMEOUT"),
		"SLEUTH_SCAN_TIMEOUT":           os.Getenv("SLEUTH_SCAN_TIMEOUT"),
		"SLEUTH_MAX_BODY_SIZE":          os.Getenv("SLEUTH_MAX_BODY_SIZE"),
		"SLEUTH_INTEL_FEED_CONFIG":      os.Getenv("SLEUTH_INTEL_FEED_CONFIG"),
		"SLEUTH_INTEL_STORAGE_DIR":      os.Getenv("SLEUTH_INTEL_STORAGE_DIR"),
		"SLEUTH_INTEL_AUTO_HYDRATE":     os.Getenv("SLEUTH_INTEL_AUTO_HYDRATE"),
		"SLEUTH_INTEL_REQUEST_TIMEOUT":  os.Getenv("SLEUTH_INTEL_REQUEST_TIMEOUT"),
		"SLEUTH_INTEL_RESOLVER_TIMEOUT": os.Getenv("SLEUTH_INTEL_RESOLVER_TIMEOUT"),
		"SLEUTH_INTEL_DNS_CACHE_TTL":    os.Getenv("SLEUTH_INTEL_DNS_CACHE_TTL"),
	}

	t.Cleanup(func() {
		for key, val := range originalEnv {
			if val == "" {
				_ = os.Unsetenv(key)
			} else {
				_ = os.Setenv(key, val)
			}
		}
	})

	_ = os.Setenv("SLEUTH_PORT", "9090")
	_ = os.Setenv("SLEUTH_READ_TIMEOUT", "45s")
	_ = os.Setenv("SLEUTH_WRITE_TIMEOUT", "45s")
	_ = os.Setenv("SLEUTH_SHUTDOWN_TIMEOUT", "45s")
	_ = os.Setenv("SLEUTH_SCAN_TIMEOUT", "120s")
	_ = os.Setenv("SLEUTH_MAX_BODY_SIZE", "204800")
	_ = os.Setenv("SLEUTH_INTEL_FEED_CONFIG", "/custom/path/feeds.json")
	_ = os.Setenv("SLEUTH_INTEL_STORAGE_DIR", "/custom/intel")
	_ = os.Setenv("SLEUTH_INTEL_AUTO_HYDRATE", "true")
	_ = os.Setenv("SLEUTH_INTEL_REQUEST_TIMEOUT", "120s")
	_ = os.Setenv("SLEUTH_INTEL_RESOLVER_TIMEOUT", "20s")
	_ = os.Setenv("SLEUTH_INTEL_DNS_CACHE_TTL", "10m")

	cfg := New()

	if cfg.Port != "9090" {
		t.Errorf("expected port 9090, got %s", cfg.Port)
	}
	if cfg.ReadTimeout != 45*time.Second {
		t.Errorf("expected read timeout 45s, got %v", cfg.ReadTimeout)
	}
	if cfg.WriteTimeout != 45*time.Second {
		t.Errorf("expected write timeout 45s, got %v", cfg.WriteTimeout)
	}
	if cfg.ShutdownTimeout != 45*time.Second {
		t.Errorf("expected shutdown timeout 45s, got %v", cfg.ShutdownTimeout)
	}
	if cfg.ScanTimeout != 120*time.Second {
		t.Errorf("expected scan timeout 120s, got %v", cfg.ScanTimeout)
	}
	if cfg.MaxBodySize != 204800 {
		t.Errorf("expected max body size 204800, got %d", cfg.MaxBodySize)
	}
	if cfg.IntelFeedConfig != "/custom/path/feeds.json" {
		t.Errorf("expected intel feed config /custom/path/feeds.json, got %s", cfg.IntelFeedConfig)
	}
	if cfg.IntelStorageDir != "/custom/intel" {
		t.Errorf("expected intel storage dir /custom/intel, got %s", cfg.IntelStorageDir)
	}
	if !cfg.IntelAutoHydrate {
		t.Error("expected intel auto hydrate true, got false")
	}
	if cfg.IntelRequestTimeout != 120*time.Second {
		t.Errorf("expected intel request timeout 120s, got %v", cfg.IntelRequestTimeout)
	}
	if cfg.IntelResolverTimeout != 20*time.Second {
		t.Errorf("expected intel resolver timeout 20s, got %v", cfg.IntelResolverTimeout)
	}
	if cfg.IntelDNSCacheTTL != 10*time.Minute {
		t.Errorf("expected intel DNS cache TTL 10m, got %v", cfg.IntelDNSCacheTTL)
	}
}

func TestBoolEnvParsing(t *testing.T) {
	testCases := []struct {
		name     string
		value    string
		expected bool
	}{
		{"true string", "true", true},
		{"True string", "True", true},
		{"TRUE string", "TRUE", true},
		{"1 string", "1", true},
		{"yes string", "yes", true},
		{"Yes string", "Yes", true},
		{"false string", "false", false},
		{"False string", "False", false},
		{"FALSE string", "FALSE", false},
		{"0 string", "0", false},
		{"no string", "no", false},
		{"No string", "No", false},
		{"empty string", "", false},
		{"invalid string", "invalid", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_ = os.Setenv("SLEUTH_INTEL_AUTO_HYDRATE", tc.value)
			t.Cleanup(func() {
				_ = os.Unsetenv("SLEUTH_INTEL_AUTO_HYDRATE")
			})

			cfg := New()
			if cfg.IntelAutoHydrate != tc.expected {
				t.Errorf("for value %q, expected %v, got %v", tc.value, tc.expected, cfg.IntelAutoHydrate)
			}
		})
	}
}

func TestInvalidDurationEnv(t *testing.T) {
	_ = os.Setenv("SLEUTH_READ_TIMEOUT", "invalid")
	t.Cleanup(func() {
		_ = os.Unsetenv("SLEUTH_READ_TIMEOUT")
	})

	cfg := New()
	if cfg.ReadTimeout != 30*time.Second {
		t.Errorf("expected fallback to default 30s for invalid duration, got %v", cfg.ReadTimeout)
	}
}

func TestInvalidInt64Env(t *testing.T) {
	_ = os.Setenv("SLEUTH_MAX_BODY_SIZE", "not-a-number")
	t.Cleanup(func() {
		_ = os.Unsetenv("SLEUTH_MAX_BODY_SIZE")
	})

	cfg := New()
	if cfg.MaxBodySize != 100*1024 {
		t.Errorf("expected fallback to default 102400 for invalid int64, got %d", cfg.MaxBodySize)
	}
}
