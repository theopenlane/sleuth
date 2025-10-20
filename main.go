package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/theopenlane/sleuth/config"
	"github.com/theopenlane/sleuth/internal/api"
	"github.com/theopenlane/sleuth/internal/intel"
	"github.com/theopenlane/sleuth/internal/scanner"
)

func main() {
	// Load configuration
	cfg := config.New()

	feedCfg, err := intel.LoadFeedConfig(cfg.IntelFeedConfig)
	if err != nil {
		log.Fatalf("Failed to load intel feed config (%s): %v", cfg.IntelFeedConfig, err)
	}

	intelClient := &http.Client{Timeout: cfg.IntelRequestTimeout}
	intelManager, err := intel.NewManager(
		feedCfg,
		intel.WithStorageDir(cfg.IntelStorageDir),
		intel.WithHTTPClient(intelClient),
		intel.WithLogger(log.Default()),
		intel.WithResolverTimeout(cfg.IntelResolverTimeout),
		intel.WithDNSCacheTTL(cfg.IntelDNSCacheTTL),
	)
	if err != nil {
		log.Fatalf("Failed to initialize intel manager: %v", err)
	}

	if cfg.IntelAutoHydrate {
		go func() {
			log.Println("Starting automatic intel hydration...")
			summary, err := intelManager.Hydrate(context.Background())
			if err != nil {
				log.Printf("Automatic intel hydration failed: %v", err)
				return
			}
			log.Printf(
				"Automatic intel hydration complete: %d feeds processed, %d indicators ingested",
				summary.SuccessfulFeeds,
				summary.TotalIndicators,
			)
		}()
	}

	// Initialize scanner
	s, err := scanner.New(
		scanner.WithVerbose(false),
		scanner.WithMaxSubdomains(50),
		scanner.WithNucleiSeverity([]string{"critical", "high", "medium"}),
	)
	if err != nil {
		log.Fatalf("Failed to initialize scanner: %v", err)
	}
	defer s.Close()

	// Initialize API router
	handler := api.NewRouter(s, intelManager, cfg.MaxBodySize, cfg.ScanTimeout)

	// Setup HTTP server
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%s", cfg.Port),
		Handler:      handler,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	}

	// Start server in goroutine
	go func() {
		log.Printf("Starting Sleuth service on :%s", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown:", err)
	}

	log.Println("Server exiting")
}
