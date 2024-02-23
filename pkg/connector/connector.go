package connector

import (
	"context"
	"fmt"
	"io"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"github.com/conductorone/baton-snyk/pkg/snyk"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
		DisplayName: "Snyk",
		Description: "Connector syncing Snyk parent group and its organizations and users to Baton",
	}, nil
}

// Validate is called to ensure that the connector is properly configured. It should exercise any API credentials
// to be sure that they are valid.
func (s *Snyk) Validate(ctx context.Context) (annotations.Annotations, error) {
	_, err := s.client.GetGroupDetails(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, fmt.Sprintf("snyk-connector: failed to validate credentials for group %s", s.GroupID))
	}

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
