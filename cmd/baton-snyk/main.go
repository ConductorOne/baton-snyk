// Package main provides the entry point for the Snyk Baton connector.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/conductorone/baton-sdk/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/field"
	"github.com/conductorone/baton-sdk/pkg/types"
	cfg "github.com/conductorone/baton-snyk/pkg/config"
	"github.com/conductorone/baton-snyk/pkg/connector"
	"github.com/conductorone/baton-snyk/pkg/snyk"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

var version = "dev"

func main() {
	ctx := context.Background()

	_, cmd, err := config.DefineConfiguration(
		ctx,
		"baton-snyk",
		getConnector,
		cfg.Config,
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

func getConnector(ctx context.Context, snykCfg *cfg.Snyk) (types.ConnectorServer, error) {
	l := ctxzap.Extract(ctx)

	err := field.Validate(cfg.Config, snykCfg)
	if err != nil {
		return nil, err
	}

	hostname := snykCfg.Hostname
	if hostname == "" {
		hostname = snyk.BaseHost
	}

	cb, err := connector.New(ctx,
		snykCfg.GroupId,
		snykCfg.ApiToken,
		snykCfg.OrgIds,
		hostname,
	)
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
