package cmd

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/knadh/koanf/providers/posflag"
	"github.com/knadh/koanf/v2"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

// appName is the name of the application used in CLI usage output
const appName = "sleuth"

// k is the global koanf instance used for configuration and flag management
var k *koanf.Koanf

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   appName,
	Short: "domain analysis sidecar service for security and technology discovery",
	PersistentPreRun: func(cmd *cobra.Command, _ []string) {
		err := initCmdFlags(cmd)
		cobra.CheckErr(err)
	},
}

// Execute adds all child commands to the root command and sets flags appropriately
func Execute() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

	defer stop()

	go func() {
		<-ctx.Done()
		log.Info().Msg("shutting down gracefully...")
	}()

	cobra.CheckErr(rootCmd.ExecuteContext(ctx))
}

// init initializes the koanf instance and registers persistent flags on the root command
func init() {
	k = koanf.New(".")
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().Bool("pretty", false, "enable pretty (human readable) logging output")
	rootCmd.PersistentFlags().Bool("debug", false, "debug logging output")
}

// initConfig reads in flags set for server startup
func initConfig() {
	if err := initCmdFlags(rootCmd); err != nil {
		log.Fatal().Err(err).Msg("error loading config")
	}

	setupLogging()
}

// initCmdFlags loads the flags from the command line into the koanf instance
func initCmdFlags(cmd *cobra.Command) error {
	return k.Load(posflag.Provider(cmd.Flags(), k.Delim(), k), nil)
}

// setupLogging configures zerolog based on the debug and pretty flags
func setupLogging() {
	level := zerolog.InfoLevel
	debug := k.Bool("debug")

	if debug {
		level = zerolog.DebugLevel
	}

	zerolog.SetGlobalLevel(level)

	if k.Bool("pretty") {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	}
}
