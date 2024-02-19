package connector

import (
	"context"
	"fmt"
	"strings"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/conductorone/baton-snyk/pkg/snyk"
)

const OrgMemberEntitlement = "member"

type orgBuilder struct {
	client *snyk.Client
	orgs   map[string]struct{}
}

func (o *orgBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return orgResourceType
}

func orgResource(ctx context.Context, org *snyk.Org, parentId *v2.ResourceId) (*v2.Resource, error) {
	profile := map[string]interface{}{
		"displayName": org.Name,
		"slug":        org.Slug,
		"url":         org.URL,
	}

	resource, err := rs.NewGroupResource(
		org.Name,
		orgResourceType,
		org.ID,
		[]rs.GroupTraitOption{
			rs.WithGroupProfile(profile),
		},
		rs.WithParentResourceID(parentId),
	)
	if err != nil {
		return nil, err
	}

	return resource, nil
}

// List returns all the orgs from the database as resource objects.
// Users include a UserTrait because they are the 'shape' of a standard org.
func (o *orgBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	if parentResourceID == nil {
		return nil, "", nil, nil
	}

	bag, page, err := parsePageToken(pToken.Token, &v2.ResourceId{ResourceType: orgResourceType.Id})
	if err != nil {
		return nil, "", nil, err
	}

	orgs, nextPageLink, err := o.client.ListOrgs(ctx, snyk.NewPaginationVars(page, ResourcesPageSize))
	if err != nil {
		return nil, "", nil, fmt.Errorf("snyk-connector: failed to list orgs: %w", err)
	}

	var rv []*v2.Resource
	for _, org := range orgs {
		if _, ok := o.orgs[org.ID]; !ok && len(o.orgs) > 0 {
			continue
		}

		orgCopy := org
		resource, err := orgResource(ctx, &orgCopy, parentResourceID)
		if err != nil {
			return nil, "", nil, fmt.Errorf("snyk-connector: failed to create org resource: %w", err)
		}

		rv = append(rv, resource)
	}

	nextPage := parseLink(nextPageLink)
	nextToken, err := bag.NextToken(nextPage)
	if err != nil {
		return nil, "", nil, err
	}

	return rv, nextToken, nil, nil
}

// Entitlements always returns an empty slice for orgs.
func (o *orgBuilder) Entitlements(ctx context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var rv []*v2.Entitlement

	// membership entitlements
	assignmentOptions := []ent.EntitlementOption{
		ent.WithGrantableTo(userResourceType),
		ent.WithDisplayName(fmt.Sprintf("%s %s", resource.DisplayName, OrgMemberEntitlement)),
		ent.WithDescription(fmt.Sprintf("Member of the %s group", resource.DisplayName)),
	}

	rv = append(rv, ent.NewAssignmentEntitlement(resource, OrgMemberEntitlement, assignmentOptions...))

	// permission entitlements - could contain custom roles
	roles, err := o.client.ListRolesInOrgs(ctx)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to list roles in group: %w", err)
	}

	for _, role := range roles {
		permissionOptions := []ent.EntitlementOption{
			ent.WithGrantableTo(userResourceType),
			ent.WithDisplayName(fmt.Sprintf("%s - %s", role.Name, role.Description)),
			ent.WithDescription(role.Description),
		}

		var roleName string
		_, err := fmt.Sscanf(role.Name, "Org %s", &roleName)
		if err != nil {
			return nil, "", nil, fmt.Errorf("failed to parse role name: %w", err)
		}

		roleName = strings.ToLower(roleName)

		rv = append(rv, ent.NewPermissionEntitlement(resource, roleName, permissionOptions...))
	}

	return rv, "", nil, nil
}

// Grants always returns an empty slice for orgs since they don't have any entitlements.
func (o *orgBuilder) Grants(ctx context.Context, resource *v2.Resource, pToken *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	var rv []*v2.Grant

	members, err := o.client.ListUsersInOrg(ctx, resource.Id.Resource)
	if err != nil {
		return nil, "", nil, fmt.Errorf("snyk-connector: failed to list users in org: %w", err)
	}

	for _, member := range members {
		userId, err := rs.NewResourceID(userResourceType, member.ID)
		if err != nil {
			return nil, "", nil, fmt.Errorf("snyk-connector: failed to create user resource id: %w", err)
		}

		// membership grants
		rv = append(rv, grant.NewGrant(resource, OrgMemberEntitlement, userId))

		// permission grants
		rv = append(rv, grant.NewGrant(resource, member.Role, userId))
	}

	return rv, "", nil, nil
}

func (o *orgBuilder) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) (annotations.Annotations, error) {
	return nil, nil
}

func (o *orgBuilder) Revoke(ctx context.Context, grant *v2.Grant) (annotations.Annotations, error) {
	return nil, nil
}

func newOrgBuilder(client *snyk.Client, orgs []string) *orgBuilder {
	orgMap := make(map[string]struct{}, len(orgs))
	for _, org := range orgs {
		orgMap[org] = struct{}{}
	}

	return &orgBuilder{
		client: client,
		orgs:   orgMap,
	}
}
