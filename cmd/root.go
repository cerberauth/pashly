package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/cerberauth/x/telemetryx"
	"github.com/spf13/cobra"
)

var (
	sqaOptOut    bool
	otelShutdown func(context.Context) error
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
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if !sqaOptOut {
				otelShutdown, _ = telemetryx.New(cmd.Context(), name, projectVersion, telemetryx.WithCommit(commit), telemetryx.WithBuildDate(date))
			}
		},
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			if otelShutdown != nil {
				_ = otelShutdown(cmd.Context())
				otelShutdown = nil
			}
		},
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
	defer func() {
		if otelShutdown != nil {
			_ = otelShutdown(context.Background())
			otelShutdown = nil
		}
	}()

	if err := c.Execute(); err != nil {
		if otelShutdown != nil {
			_ = otelShutdown(context.Background())
			otelShutdown = nil
		}

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
