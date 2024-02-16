package connector

import (
	"context"
	"io"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"github.com/conductorone/baton-snyk/pkg/snyk"
)

type Snyk struct {
	client  *snyk.Client
	GroupID string
	Orgs    []string
}

// ResourceSyncers returns a ResourceSyncer for each resource type that should be synced from the upstream service.
func (s *Snyk) ResourceSyncers(ctx context.Context) []connectorbuilder.ResourceSyncer {
	return []connectorbuilder.ResourceSyncer{
		newGroupBuilder(s.client, s.GroupID),
		newOrgBuilder(s.client, s.Orgs),
		newUserBuilder(s.client),
	}
}

// Asset takes an input AssetRef and attempts to fetch it using the connector's authenticated http client
// It streams a response, always starting with a metadata object, following by chunked payloads for the asset.
func (s *Snyk) Asset(ctx context.Context, asset *v2.AssetRef) (string, io.ReadCloser, error) {
	return "", nil, nil
}

// Metadata returns metadata about the connector.
func (s *Snyk) Metadata(ctx context.Context) (*v2.ConnectorMetadata, error) {
	return &v2.ConnectorMetadata{
		DisplayName: "My Baton Connector",
		Description: "The template implementation of a baton connector",
	}, nil
}

// Validate is called to ensure that the connector is properly configured. It should exercise any API credentials
// to be sure that they are valid.
func (s *Snyk) Validate(ctx context.Context) (annotations.Annotations, error) {
	return nil, nil
}

// New returns a new instance of the connector.
func New(ctx context.Context, groupID, token string, orgs []string) (*Snyk, error) {
	httpClient, err := uhttp.NewClient(ctx, uhttp.WithLogger(true, nil))
	if err != nil {
		return nil, err
	}

	return &Snyk{
		client:  snyk.NewClient(httpClient, groupID, token),
		GroupID: groupID,
		Orgs:    orgs,
	}, nil
}
