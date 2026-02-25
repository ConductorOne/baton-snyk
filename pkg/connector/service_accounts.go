package connector

import (
	"context"
	"fmt"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/conductorone/baton-snyk/pkg/snyk"
)

type serviceAccountBuilder struct {
	client *snyk.Client
}

func (s *serviceAccountBuilder) ResourceType(_ context.Context) *v2.ResourceType {
	return serviceAccountResourceType
}

func serviceAccountResource(sa *snyk.ServiceAccountData, parentID *v2.ResourceId) (*v2.Resource, error) {
	resource, err := rs.NewUserResource(
		sa.Attributes.Name,
		serviceAccountResourceType,
		sa.ID,
		[]rs.UserTraitOption{
			rs.WithAccountType(v2.UserTrait_ACCOUNT_TYPE_SERVICE),
			rs.WithStatus(v2.UserTrait_Status_STATUS_ENABLED),
			rs.WithUserProfile(map[string]interface{}{
				"auth_type": sa.Attributes.AuthType,
				"level":     sa.Attributes.Level,
			}),
		},
		rs.WithParentResourceID(parentID),
		rs.WithExternalID(&v2.ExternalId{Id: sa.ID}),
	)
	if err != nil {
		return nil, err
	}

	return resource, nil
}

// List returns service accounts as resource objects.
// When the parent is a group resource, group-level service accounts are listed.
// When the parent is an org resource, org-level service accounts are listed.
func (s *serviceAccountBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	if parentResourceID == nil {
		return nil, "", nil, nil
	}

	if pToken == nil {
		pToken = &pagination.Token{}
	}

	bag, page, err := parsePageToken(pToken.Token, &v2.ResourceId{ResourceType: serviceAccountResourceType.Id})
	if err != nil {
		return nil, "", nil, fmt.Errorf("snyk-connector: failed to parse page token: %w", err)
	}

	var (
		saResp *snyk.ServiceAccountListResponse
		link   string
	)

	switch parentResourceID.ResourceType {
	case groupResourceType.Id:
		saResp, link, err = s.client.ListGroupServiceAccounts(ctx, page)
		if err != nil {
			return nil, "", nil, fmt.Errorf("snyk-connector: failed to list group service accounts: %w", err)
		}
	case orgResourceType.Id:
		saResp, link, err = s.client.ListOrgServiceAccounts(ctx, parentResourceID.Resource, page)
		if err != nil {
			return nil, "", nil, fmt.Errorf("snyk-connector: failed to list org service accounts for org %s: %w", parentResourceID.Resource, err)
		}
	default:
		return nil, "", nil, nil
	}

	// Both endpoints return group and org SAs mixed together.
	// Filter by level so each SA appears under exactly one parent.
	expectedLevel := "Group"
	if parentResourceID.ResourceType == orgResourceType.Id {
		expectedLevel = "Org"
	}

	var rv []*v2.Resource
	for i := range saResp.Data {
		if saResp.Data[i].Attributes.Level != expectedLevel {
			continue
		}
		resource, err := serviceAccountResource(&saResp.Data[i], parentResourceID)
		if err != nil {
			return nil, "", nil, fmt.Errorf("snyk-connector: failed to create service account resource: %w", err)
		}
		rv = append(rv, resource)
	}

	nextPageURL := parseRestNextLink(link)
	nextToken, err := bag.NextToken(nextPageURL)
	if err != nil {
		return nil, "", nil, fmt.Errorf("snyk-connector: failed to create next page token: %w", err)
	}

	return rv, nextToken, nil, nil
}

// Entitlements always returns an empty slice for service accounts.
func (s *serviceAccountBuilder) Entitlements(_ context.Context, _ *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

// Grants always returns an empty slice for service accounts.
// Grants are emitted by the group and org builders that own the entitlements.
func (s *serviceAccountBuilder) Grants(_ context.Context, _ *v2.Resource, _ *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func newServiceAccountBuilder(client *snyk.Client) *serviceAccountBuilder {
	return &serviceAccountBuilder{
		client: client,
	}
}
