package main

import (
	"context"
	"fmt"
	"os"

	configSchema "github.com/conductorone/baton-sdk/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/field"
	"github.com/conductorone/baton-sdk/pkg/types"
	"github.com/conductorone/baton-snyk/pkg/connector"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

const (
	version       = "dev"
	connectorName = "baton-snyk"
)

var (
	APIToken            = field.StringField(connector.APIToken, field.WithRequired(true), field.WithDescription("API token representing user or service account, used to authenticate with Snyk API."))
	GroupID             = field.StringField(connector.GroupID, field.WithRequired(true), field.WithDescription("Snyk group ID to scope the synchronization."))
	OrganizationIDs     = field.StringField(connector.OrgIDs, field.WithDescription("Limit syncing to specified organizations."))
	configurationFields = []field.SchemaField{APIToken, GroupID, OrganizationIDs}
	ctx                 = context.Background()
)

func main() {
	_, cmd, err := configSchema.DefineConfiguration(ctx,
		connectorName,
		getConnector,
		field.NewConfiguration(configurationFields),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	cmd.Version = version
	err = cmd.Execute()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func getConnector(ctx context.Context, cfg *viper.Viper) (types.ConnectorServer, error) {
	l := ctxzap.Extract(ctx)
	cb, err := connector.New(ctx, cfg)
	if err != nil {
		l.Error("error creating connector", zap.Error(err))
		return nil, err
	}

	c, err := connectorbuilder.NewConnector(ctx, cb)
	if err != nil {
		l.Error("error creating connector", zap.Error(err))
		return nil, err
	}

	return c, nil
}
