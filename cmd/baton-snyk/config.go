package main

import (
	"context"
	"fmt"

	"github.com/conductorone/baton-sdk/pkg/cli"
	"github.com/spf13/cobra"
)

// config defines the external configuration required for the connector to run.
type config struct {
	cli.BaseConfig `mapstructure:",squash"` // Puts the base config options in the same place as the connector options

	APIToken string   `mapstructure:"api-token"`
	GroupID  string   `mapstructure:"group-id"`
	OrgIDs   []string `mapstructure:"org-ids"`
}

// validateConfig is run after the configuration is loaded, and should return an error if it isn't valid.
func validateConfig(ctx context.Context, cfg *config) error {
	if cfg.APIToken == "" {
		return fmt.Errorf("api-token is required, use --help for more information")
	}

	if cfg.GroupID == "" {
		return fmt.Errorf("group-id is required, use --help for more information")
	}

	return nil
}

func cmdFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().String("api-token", "", "API token representing user or service account, used to authenticate with Snyk API. ($BATON_API_TOKEN)")
	cmd.PersistentFlags().String("group-id", "", "Snyk group ID to scope the synchronization. ($BATON_GROUP_ID)")
	cmd.PersistentFlags().StringSlice("org-ids", nil, "Limit syncing to specified organizations. ($BATON_ORG_IDS)")
}
