package config

import (
	"strings"
	"time"

	"github.com/knadh/koanf/parsers/yaml"
	env "github.com/knadh/koanf/providers/env/v2"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
	"github.com/mcuadros/go-defaults"
	"github.com/rs/zerolog/log"
)

// envVarPrefix is the prefix for environment variables used to override config values
const envVarPrefix = "SLEUTH_"

// defaultConfigFilePath is the default path to the YAML configuration file
var defaultConfigFilePath = "./config/.config.yaml"

// Config contains the configuration for the sleuth service
type Config struct {
	// Server contains HTTP server settings
	Server Server `json:"server" koanf:"server"`
	// Scanner contains domain scanner settings
	Scanner Scanner `json:"scanner" koanf:"scanner"`
	// Intel contains threat intelligence settings
	Intel Intel `json:"intel" koanf:"intel"`
	// Cloudflare contains Cloudflare API settings
	Cloudflare Cloudflare `json:"cloudflare" koanf:"cloudflare"`
	// Slack contains Slack webhook settings
	Slack Slack `json:"slack" koanf:"slack"`
}

// Server contains HTTP server configuration
type Server struct {
	// Debug enables debug mode, set via command line flag
	Debug bool `json:"-" koanf:"-" default:"false"`
	// Pretty enables pretty logging output, set via command line flag
	Pretty bool `json:"-" koanf:"-" default:"false"`
	// Listen sets the address and port to serve on
	Listen string `json:"listen" koanf:"listen" default:":8080"`
	// ReadTimeout is the maximum duration for reading the entire request
	ReadTimeout time.Duration `json:"readtimeout" koanf:"readtimeout" default:"30s"`
	// WriteTimeout is the maximum duration before timing out writes of the response
	WriteTimeout time.Duration `json:"writetimeout" koanf:"writetimeout" default:"180s"`
	// ShutdownGracePeriod is the grace period for in-flight requests before shutting down
	ShutdownGracePeriod time.Duration `json:"shutdowngraceperiod" koanf:"shutdowngraceperiod" default:"30s"`
	// MaxBodySize is the maximum allowed request body size in bytes
	MaxBodySize int64 `json:"maxbodysize" koanf:"maxbodysize" default:"102400"`
}

// Scanner contains domain scanner configuration
type Scanner struct {
	// Timeout is the maximum duration for a scan operation
	Timeout time.Duration `json:"timeout" koanf:"timeout" default:"120s"`
	// MaxSubdomains is the maximum number of subdomains to enumerate
	MaxSubdomains int `json:"maxsubdomains" koanf:"maxsubdomains" default:"50"`
	// NucleiSeverity is the list of nuclei severity levels to scan for
	NucleiSeverity []string `json:"nucleiseverity" koanf:"nucleiseverity"`
	// Verbose enables verbose scanner output
	Verbose bool `json:"verbose" koanf:"verbose" default:"false"`
}

// Intel contains threat intelligence configuration
type Intel struct {
	// FeedConfig is the path to the feed configuration JSON file
	FeedConfig string `json:"feedconfig" koanf:"feedconfig" default:"config/feed_config.json"`
	// StorageDir is the directory for storing downloaded feed data
	StorageDir string `json:"storagedir" koanf:"storagedir" default:"data/intel"`
	// AutoHydrate enables automatic feed hydration on startup
	AutoHydrate bool `json:"autohydrate" koanf:"autohydrate" default:"false"`
	// RequestTimeout is the timeout for individual feed download requests
	RequestTimeout time.Duration `json:"requesttimeout" koanf:"requesttimeout" default:"90s"`
	// ResolverTimeout is the timeout for DNS lookups during scoring
	ResolverTimeout time.Duration `json:"resolvertimeout" koanf:"resolvertimeout" default:"10s"`
	// DNSCacheTTL is the TTL for cached DNS responses
	DNSCacheTTL time.Duration `json:"dnscachettl" koanf:"dnscachettl" default:"5m"`
}

// Cloudflare contains Cloudflare API configuration
type Cloudflare struct {
	// AccountID is the Cloudflare account identifier
	AccountID string `json:"accountid" koanf:"accountid"`
	// APIToken is the bearer token for Cloudflare API authentication
	APIToken string `json:"apitoken" koanf:"apitoken"`
	// RequestTimeout is the timeout for Cloudflare API requests
	RequestTimeout time.Duration `json:"requesttimeout" koanf:"requesttimeout" default:"30s"`
}

// Slack contains Slack webhook configuration
type Slack struct {
	// WebhookURL is the Slack incoming webhook URL
	WebhookURL string `json:"webhookurl" koanf:"webhookurl"`
	// RequestTimeout is the timeout for Slack webhook requests
	RequestTimeout time.Duration `json:"requesttimeout" koanf:"requesttimeout" default:"10s"`
}

// Option configures the Config
type Option func(*Config)

// New creates a Config with defaults applied and any supplied options
func New(opts ...Option) *Config {
	cfg := &Config{}
	defaults.SetDefaults(cfg)

	// set default nuclei severity since go-defaults does not handle slices
	if len(cfg.Scanner.NucleiSeverity) == 0 {
		cfg.Scanner.NucleiSeverity = []string{"critical", "high", "medium"}
	}

	for _, opt := range opts {
		opt(cfg)
	}

	return cfg
}

// Load reads configuration from a YAML file and environment variables
// Settings are layered: defaults, then config file, then environment variables,
// with later sources overwriting earlier ones
func Load(cfgFile *string) (*Config, error) {
	k := koanf.New(".")

	if cfgFile == nil || *cfgFile == "" {
		*cfgFile = defaultConfigFilePath
	}

	if err := k.Load(file.Provider(*cfgFile), yaml.Parser()); err != nil {
		log.Warn().Err(err).Msg("failed to load config file, proceeding with defaults and environment variables")
	}

	if err := k.Load(env.Provider(".", env.Opt{
		Prefix: envVarPrefix,
		TransformFunc: func(key, v string) (string, any) {
			key = strings.ToLower(strings.TrimPrefix(key, envVarPrefix))
			key = strings.ReplaceAll(key, "_", ".")

			if strings.Contains(v, ",") {
				return key, strings.Split(v, ",")
			}

			return key, v
		},
	}), nil); err != nil {
		log.Warn().Err(err).Msg("failed to load env vars")
	}

	conf := New()
	if err := k.Unmarshal("", &conf); err != nil {
		return nil, ErrConfigUnmarshal
	}

	return conf, nil
}
