package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/theopenlane/sleuth/config"
	"github.com/theopenlane/sleuth/internal/api"
	"github.com/theopenlane/sleuth/internal/cloudflare"
	"github.com/theopenlane/sleuth/internal/compliance"
	"github.com/theopenlane/sleuth/internal/emailauth"
	"github.com/theopenlane/sleuth/internal/intel"
	"github.com/theopenlane/sleuth/internal/rdap"
	"github.com/theopenlane/sleuth/internal/scanner"
	"github.com/theopenlane/sleuth/internal/slack"
)

// serveCmd is the cobra command that starts the sleuth API server
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "start the sleuth api server",
	Run: func(cmd *cobra.Command, _ []string) {
		err := serve(cmd.Context())
		cobra.CheckErr(err)
	},
}

// init registers the serve command and its flags on the root command
func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.PersistentFlags().String("config", "./config/.config.yaml", "config file location")
}

// serve initializes dependencies and starts the sleuth API server
func serve(ctx context.Context) error {
	cfgPath := k.String("config")

	cfg, err := config.Load(&cfgPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	cfg.Server.Debug = k.Bool("debug")
	cfg.Server.Pretty = k.Bool("pretty")

	intelManager, err := setupIntel(ctx, cfg)
	if err != nil {
		return fmt.Errorf("setting up intel: %w", err)
	}

	s, err := setupScanner(cfg)
	if err != nil {
		return fmt.Errorf("setting up scanner: %w", err)
	}

	defer func() { _ = s.Close() }()

	cfClient := setupCloudflare(cfg)
	slackClient := setupSlack(cfg)
	discoverer := setupComplianceDiscoverer()

	handler := api.NewRouter(api.RouterConfig{
		Scanner:      s,
		IntelManager: intelManager,
		Enricher:     cfClient,
		Discoverer:   discoverer,
		Notifier:     slackClient,
		MaxBodySize:  cfg.Server.MaxBodySize,
		ScanTimeout:  cfg.Scanner.Timeout,
	})

	srv := &http.Server{
		Addr:         cfg.Server.Listen,
		Handler:      handler,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	go func() {
		<-ctx.Done()

		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownGracePeriod)
		defer cancel()

		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Error().Err(err).Msg("server shutdown error")
		}
	}()

	log.Info().Str("listen", cfg.Server.Listen).Msg("starting sleuth service")

	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("listen: %w", err)
	}

	return nil
}

// setupIntel initializes the threat intelligence manager from config
func setupIntel(ctx context.Context, cfg *config.Config) (*intel.Manager, error) {
	feedCfg, err := intel.LoadFeedConfig(cfg.Intel.FeedConfig)
	if err != nil {
		return nil, fmt.Errorf("loading feed config from %s: %w", cfg.Intel.FeedConfig, err)
	}

	intelClient := &http.Client{Timeout: cfg.Intel.RequestTimeout}

	emailAuthAnalyzer := emailauth.NewAnalyzer()
	rdapClient := rdap.NewClient()

	manager, err := intel.NewManager(
		feedCfg,
		intel.WithStorageDir(cfg.Intel.StorageDir),
		intel.WithHTTPClient(intelClient),
		intel.WithResolverTimeout(cfg.Intel.ResolverTimeout),
		intel.WithDNSCacheTTL(cfg.Intel.DNSCacheTTL),
		intel.WithEmailAuthAnalyzer(emailAuthAnalyzer),
		intel.WithRDAPAnalyzer(rdapClient),
	)
	if err != nil {
		return nil, fmt.Errorf("initializing intel manager: %w", err)
	}

	if cfg.Intel.AutoHydrate {
		go func() {
			log.Info().Msg("starting automatic intel hydration")

			summary, hydrateErr := manager.Hydrate(ctx)
			if hydrateErr != nil {
				log.Error().Err(hydrateErr).Msg("automatic intel hydration failed")
				return
			}

			log.Info().Int("feeds", summary.SuccessfulFeeds).Int("indicators", summary.TotalIndicators).Msg("automatic intel hydration complete")
		}()
	}

	return manager, nil
}

// setupScanner initializes the domain scanner from config
func setupScanner(cfg *config.Config) (*scanner.Scanner, error) {
	opts := []scanner.ScanOption{
		scanner.WithVerbose(cfg.Scanner.Verbose),
		scanner.WithMaxSubdomains(cfg.Scanner.MaxSubdomains),
	}

	if len(cfg.Scanner.NucleiSeverity) > 0 {
		opts = append(opts, scanner.WithNucleiSeverity(cfg.Scanner.NucleiSeverity))
	}

	return scanner.New(opts...)
}

// setupCloudflare initializes the Cloudflare client from config, returning nil when unconfigured
func setupCloudflare(cfg *config.Config) *cloudflare.Client {
	log.Info().Int("account_id_len", len(cfg.Cloudflare.AccountID)).Bool("api_token_set", cfg.Cloudflare.APIToken != "").Msg("cloudflare config check")

	if cfg.Cloudflare.AccountID == "" || cfg.Cloudflare.APIToken == "" {
		log.Info().Msg("cloudflare enrichment not configured, skipping")
		return nil
	}

	client, err := cloudflare.New(
		cfg.Cloudflare.AccountID,
		cfg.Cloudflare.APIToken,
		cloudflare.WithHTTPClient(&http.Client{Timeout: cfg.Cloudflare.RequestTimeout}),
	)
	if err != nil {
		log.Warn().Err(err).Msg("failed to initialize cloudflare client")
		return nil
	}

	log.Info().Msg("cloudflare enrichment configured")

	return client
}

// setupComplianceDiscoverer initializes the httpx-based compliance page discoverer
func setupComplianceDiscoverer() compliance.Discoverer {
	log.Info().Msg("compliance discoverer configured")

	return compliance.NewHTTPXDiscoverer()
}

// setupSlack initializes the Slack webhook client from config, returning nil when unconfigured
func setupSlack(cfg *config.Config) *slack.Client {
	if cfg.Slack.WebhookURL == "" {
		log.Info().Msg("slack notifications not configured, skipping")
		return nil
	}

	client, err := slack.New(
		cfg.Slack.WebhookURL,
		slack.WithHTTPClient(&http.Client{Timeout: cfg.Slack.RequestTimeout}),
	)
	if err != nil {
		log.Warn().Err(err).Msg("failed to initialize slack client")
		return nil
	}

	log.Info().Msg("slack notifications configured")

	return client
}
