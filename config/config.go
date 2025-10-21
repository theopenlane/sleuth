package config

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Config holds service configuration
type Config struct {
	Port                 string
	ReadTimeout          time.Duration
	WriteTimeout         time.Duration
	ShutdownTimeout      time.Duration
	ScanTimeout          time.Duration
	MaxBodySize          int64
	IntelFeedConfig      string
	IntelStorageDir      string
	IntelAutoHydrate     bool
	IntelRequestTimeout  time.Duration
	IntelResolverTimeout time.Duration
	IntelDNSCacheTTL     time.Duration
}

// New creates a new configuration from environment variables
func New() *Config {
	return &Config{
		Port:                 getEnv("SLEUTH_PORT", "8080"),
		ReadTimeout:          getDurationEnv("SLEUTH_READ_TIMEOUT", 30*time.Second),
		WriteTimeout:         getDurationEnv("SLEUTH_WRITE_TIMEOUT", 180*time.Second),
		ShutdownTimeout:      getDurationEnv("SLEUTH_SHUTDOWN_TIMEOUT", 30*time.Second),
		ScanTimeout:          getDurationEnv("SLEUTH_SCAN_TIMEOUT", 120*time.Second),
		MaxBodySize:          getInt64Env("SLEUTH_MAX_BODY_SIZE", 100*1024), // 100KB
		IntelFeedConfig:      getEnv("SLEUTH_INTEL_FEED_CONFIG", filepath.Join("config", "feed_config.json")),
		IntelStorageDir:      getEnv("SLEUTH_INTEL_STORAGE_DIR", filepath.Join("data", "intel")),
		IntelAutoHydrate:     getBoolEnv("SLEUTH_INTEL_AUTO_HYDRATE", false),
		IntelRequestTimeout:  getDurationEnv("SLEUTH_INTEL_REQUEST_TIMEOUT", 90*time.Second),
		IntelResolverTimeout: getDurationEnv("SLEUTH_INTEL_RESOLVER_TIMEOUT", 10*time.Second),
		IntelDNSCacheTTL:     getDurationEnv("SLEUTH_INTEL_DNS_CACHE_TTL", 5*time.Minute),
	}
}

// getEnv gets an environment variable with a default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getBoolEnv(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if value == "1" || strings.EqualFold(value, "true") || strings.EqualFold(value, "yes") {
			return true
		}
		if value == "0" || strings.EqualFold(value, "false") || strings.EqualFold(value, "no") {
			return false
		}
	}
	return defaultValue
}

// getDurationEnv gets a duration environment variable with a default value
func getDurationEnv(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}

// getInt64Env gets an int64 environment variable with a default value
func getInt64Env(key string, defaultValue int64) int64 {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.ParseInt(value, 10, 64); err == nil {
			return intValue
		}
	}
	return defaultValue
}
