package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/cerberauth/x/telemetryx"
	"github.com/spf13/cobra"
)

// argvioAPIKey is pashly's public_ingest-scoped Argvio API key, selecting the
// "pashly" tenant its usage analytics land in. It only allows sending usage
// data, so it is safe to embed.
const argvioAPIKey = "argv_live_pub_WHeri42_aw0HKtDtc3YOaGjinIs_w_Ir" //nolint:gosec // ingest-only key, not a secret

var (
	sqaOptOut bool
)

var name = "pashly"

func NewRootCmd(projectVersion, commit, date string) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:     name,
		Version: projectVersion + " (commit=" + commit + ", built=" + date + ")",
		Short:   "Password generation, hashing, and verification CLI",
		Long: `Pashly generates passwords, hashes them with configurable parameters, and
verifies passwords against hashes — built to support IAM/CIAM migration work
(moving user stores between systems like Auth0, Okta, Keycloak, and
Duende IdentityServer).`,
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	rootCmd.AddCommand(generateCmd)
	rootCmd.AddCommand(hashCmd)
	rootCmd.AddCommand(verifyCmd)
	rootCmd.AddCommand(infoCmd)

	rootCmd.PersistentFlags().BoolVarP(&sqaOptOut, "sqa-opt-out", "", false, "Opt out of sending anonymous usage statistics and crash reports to help improve the tool")

	return rootCmd
}

// Execute adds all child commands to the root command and sets flags
// appropriately. This is called by main.main(). It only needs to happen
// once to the RootCmd.
func Execute(projectVersion, commit, date string) {
	c := NewRootCmd(projectVersion, commit, date)
	argvioShutdown := telemetryx.Instrument(c, projectVersion, argvioAPIKey)
	defer func() { _ = argvioShutdown(context.Background()) }()

	if err := telemetryx.Execute(c); err != nil {
		_ = argvioShutdown(context.Background())

		code := 2
		var exitErr *exitCodeError
		if errors.As(err, &exitErr) {
			code = exitErr.code
			if exitErr.err == nil {
				// nolint: gocritic // false positive
				os.Exit(code)
			}
		}

		fmt.Fprintln(os.Stderr, err)
		// nolint: gocritic // false positive
		os.Exit(code)
	}
}
