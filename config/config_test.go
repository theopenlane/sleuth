package config

import (
	"os"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	cfg := New()

	if cfg.Server.Listen != ":8080" {
		t.Errorf("expected default listen :8080, got %s", cfg.Server.Listen)
	}

	if cfg.Server.ReadTimeout != 30*time.Second {
		t.Errorf("expected default read timeout 30s, got %v", cfg.Server.ReadTimeout)
	}

	if cfg.Server.WriteTimeout != 180*time.Second {
		t.Errorf("expected default write timeout 180s, got %v", cfg.Server.WriteTimeout)
	}

	if cfg.Server.ShutdownGracePeriod != 30*time.Second {
		t.Errorf("expected default shutdown grace period 30s, got %v", cfg.Server.ShutdownGracePeriod)
	}

	if cfg.Scanner.Timeout != 120*time.Second {
		t.Errorf("expected default scan timeout 120s, got %v", cfg.Scanner.Timeout)
	}

	if cfg.Server.MaxBodySize != 102400 {
		t.Errorf("expected default max body size 102400, got %d", cfg.Server.MaxBodySize)
	}

	if len(cfg.Scanner.NucleiSeverity) != 5 {
		t.Errorf("expected 5 default nuclei severity levels, got %d", len(cfg.Scanner.NucleiSeverity))
	}

	if cfg.Intel.FeedConfig != "config/feed_config.json" {
		t.Errorf("expected default feed config path, got %s", cfg.Intel.FeedConfig)
	}

	if cfg.Intel.StorageDir != "data/intel" {
		t.Errorf("expected default storage dir, got %s", cfg.Intel.StorageDir)
	}

	if cfg.Cloudflare.RequestTimeout != 30*time.Second {
		t.Errorf("expected default cloudflare request timeout 30s, got %v", cfg.Cloudflare.RequestTimeout)
	}

	if cfg.Cloudflare.AccountID != "" {
		t.Errorf("expected empty default cloudflare account ID, got %s", cfg.Cloudflare.AccountID)
	}

	if cfg.Slack.RequestTimeout != 10*time.Second {
		t.Errorf("expected default slack request timeout 10s, got %v", cfg.Slack.RequestTimeout)
	}

	if cfg.Slack.WebhookURL != "" {
		t.Errorf("expected empty default slack webhook URL, got %s", cfg.Slack.WebhookURL)
	}
}

func TestNewWithEnvVars(t *testing.T) {
	envVars := map[string]string{
		"SLEUTH_SERVER_LISTEN":              ":9090",
		"SLEUTH_SERVER_READTIMEOUT":         "45s",
		"SLEUTH_SERVER_WRITETIMEOUT":        "45s",
		"SLEUTH_SERVER_SHUTDOWNGRACEPERIOD": "45s",
		"SLEUTH_SERVER_MAXBODYSIZE":         "204800",
		"SLEUTH_SCANNER_TIMEOUT":            "120s",
		"SLEUTH_INTEL_FEEDCONFIG":           "/custom/path/feeds.json",
		"SLEUTH_INTEL_STORAGEDIR":           "/custom/intel",
		"SLEUTH_INTEL_AUTOHYDRATE":          "true",
		"SLEUTH_INTEL_REQUESTTIMEOUT":       "120s",
		"SLEUTH_INTEL_RESOLVERTIMEOUT":      "20s",
		"SLEUTH_INTEL_DNSCACHETTL":          "10m",
		"SLEUTH_CLOUDFLARE_ACCOUNTID":       "test-account-id",
		"SLEUTH_CLOUDFLARE_APITOKEN":        "test-api-token",
		"SLEUTH_CLOUDFLARE_REQUESTTIMEOUT":  "60s",
		"SLEUTH_SLACK_WEBHOOKURL":           "https://hooks.slack.com/test",
		"SLEUTH_SLACK_REQUESTTIMEOUT":       "15s",
	}

	for key, val := range envVars {
		t.Setenv(key, val)
	}

	noFile := ""
	cfg, err := Load(&noFile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Server.Listen != ":9090" {
		t.Errorf("expected listen :9090, got %s", cfg.Server.Listen)
	}

	if cfg.Server.ReadTimeout != 45*time.Second {
		t.Errorf("expected read timeout 45s, got %v", cfg.Server.ReadTimeout)
	}

	if cfg.Server.WriteTimeout != 45*time.Second {
		t.Errorf("expected write timeout 45s, got %v", cfg.Server.WriteTimeout)
	}

	if cfg.Server.ShutdownGracePeriod != 45*time.Second {
		t.Errorf("expected shutdown grace period 45s, got %v", cfg.Server.ShutdownGracePeriod)
	}

	if cfg.Server.MaxBodySize != 204800 {
		t.Errorf("expected max body size 204800, got %d", cfg.Server.MaxBodySize)
	}

	if cfg.Intel.FeedConfig != "/custom/path/feeds.json" {
		t.Errorf("expected intel feed config /custom/path/feeds.json, got %s", cfg.Intel.FeedConfig)
	}

	if cfg.Intel.StorageDir != "/custom/intel" {
		t.Errorf("expected intel storage dir /custom/intel, got %s", cfg.Intel.StorageDir)
	}

	if !cfg.Intel.AutoHydrate {
		t.Error("expected intel auto hydrate true, got false")
	}

	if cfg.Intel.RequestTimeout != 120*time.Second {
		t.Errorf("expected intel request timeout 120s, got %v", cfg.Intel.RequestTimeout)
	}

	if cfg.Intel.ResolverTimeout != 20*time.Second {
		t.Errorf("expected intel resolver timeout 20s, got %v", cfg.Intel.ResolverTimeout)
	}

	if cfg.Intel.DNSCacheTTL != 10*time.Minute {
		t.Errorf("expected intel DNS cache TTL 10m, got %v", cfg.Intel.DNSCacheTTL)
	}

	if cfg.Cloudflare.AccountID != "test-account-id" {
		t.Errorf("expected cloudflare account ID test-account-id, got %s", cfg.Cloudflare.AccountID)
	}

	if cfg.Cloudflare.APIToken != "test-api-token" {
		t.Errorf("expected cloudflare API token test-api-token, got %s", cfg.Cloudflare.APIToken)
	}

	if cfg.Cloudflare.RequestTimeout != 60*time.Second {
		t.Errorf("expected cloudflare request timeout 60s, got %v", cfg.Cloudflare.RequestTimeout)
	}

	if cfg.Slack.WebhookURL != "https://hooks.slack.com/test" {
		t.Errorf("expected slack webhook URL https://hooks.slack.com/test, got %s", cfg.Slack.WebhookURL)
	}

	if cfg.Slack.RequestTimeout != 15*time.Second {
		t.Errorf("expected slack request timeout 15s, got %v", cfg.Slack.RequestTimeout)
	}
}

func TestLoadWithMissingFile(t *testing.T) {
	path := "/nonexistent/path/config.yaml"
	cfg, err := Load(&path)
	if err != nil {
		t.Fatalf("expected no error with missing config file, got %v", err)
	}

	if cfg.Server.Listen != ":8080" {
		t.Errorf("expected default listen :8080 with missing file, got %s", cfg.Server.Listen)
	}
}

func TestLoadWithYAMLFile(t *testing.T) {
	content := []byte(`
server:
  listen: ":9999"
  readtimeout: 60s
scanner:
  maxsubdomains: 100
intel:
  autohydrate: true
`)
	tmpFile, err := os.CreateTemp(t.TempDir(), "config-*.yaml")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	if _, err := tmpFile.Write(content); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	if err := tmpFile.Close(); err != nil {
		t.Fatalf("failed to close temp file: %v", err)
	}

	path := tmpFile.Name()
	cfg, err := Load(&path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Server.Listen != ":9999" {
		t.Errorf("expected listen :9999, got %s", cfg.Server.Listen)
	}

	if cfg.Server.ReadTimeout != 60*time.Second {
		t.Errorf("expected read timeout 60s, got %v", cfg.Server.ReadTimeout)
	}

	if cfg.Scanner.MaxSubdomains != 100 {
		t.Errorf("expected max subdomains 100, got %d", cfg.Scanner.MaxSubdomains)
	}

	if !cfg.Intel.AutoHydrate {
		t.Error("expected auto hydrate true from YAML, got false")
	}
}
