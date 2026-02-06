package connector

import (
	"context"
	"fmt"
	"slices"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/conductorone/baton-snyk/pkg/snyk"
)

// Group role constants for Snyk.
const (
	AdminRole  = "admin"
	MemberRole = "member"
	ViewerRole = "viewer"
)

var groupRoles = []string{AdminRole, MemberRole, ViewerRole}

type groupBuilder struct {
	client *snyk.Client
	ID     string
	orgs   map[string]struct{}
}

func (g *groupBuilder) ResourceType(_ context.Context) *v2.ResourceType {
	return groupResourceType
}

func groupResource(_ context.Context, group *snyk.Group) (*v2.Resource, error) {
	profile := map[string]interface{}{
		"displayName": group.Name,
		"url":         group.URL,
	}

	resource, err := rs.NewGroupResource(
		group.Name,
		groupResourceType,
		group.ID,
		[]rs.GroupTraitOption{
			rs.WithGroupProfile(profile),
		},
		rs.WithAnnotation(
			&v2.ChildResourceType{ResourceTypeId: orgResourceType.Id},
			&v2.ChildResourceType{ResourceTypeId: userResourceType.Id},
		),
	)
	if err != nil {
		return nil, err
	}

	return resource, nil
}

// List returns all the groups from the database as resource objects.
// Groups include a GroupTrait because they are the 'shape' of a standard group.
func (g *groupBuilder) List(ctx context.Context, _ *v2.ResourceId, _ *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	var rv []*v2.Resource

	// get details from orgs endpoint
	groupDetail, err := g.client.GetGroupDetails(ctx)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to get group details: %w", err)
	}

	gr, err := groupResource(ctx, groupDetail)
	if err != nil {
		return nil, "", nil, err
	}

	rv = append(rv, gr)

	return rv, "", nil, nil
}

// Entitlements returns all default permission entitlements for a group.
func (g *groupBuilder) Entitlements(_ context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var rv []*v2.Entitlement

	for _, role := range groupRoles {
		permissionOptions := []ent.EntitlementOption{
			ent.WithGrantableTo(userResourceType),
			ent.WithDisplayName(fmt.Sprintf("%s %s", resource.DisplayName, role)),
			ent.WithDescription(fmt.Sprintf("%s role in the %s group", role, resource.DisplayName)),
		}

		rv = append(rv, ent.NewPermissionEntitlement(resource, role, permissionOptions...))
	}

	return rv, "", nil, nil
}

// Grants returns all the permission grants for a group.
func (g *groupBuilder) Grants(ctx context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	var rv []*v2.Grant

	members, err := g.client.ListUsersInGroup(ctx)
	if err != nil {
		return nil, "", nil, fmt.Errorf("snyk-connector: failed to list users in group: %w", err)
	}

	// Get all organizations in the group to create member grants for group admins
	var orgResources []*v2.Resource
	pageToken := ""
	for {
		orgs, nextPageLink, err := g.client.ListOrgs(ctx, snyk.NewPaginationVars(pageToken, ResourcesPageSize))
		if err != nil {
			return nil, "", nil, fmt.Errorf("snyk-connector: failed to list orgs: %w", err)
		}

		// Build org resources, applying the same filter as orgBuilder
		for _, org := range orgs {
			// Filter by org IDs if filter is specified
			if _, ok := g.orgs[org.ID]; !ok && len(g.orgs) > 0 {
				continue
			}

			orgResource, err := rs.NewGroupResource(
				org.Name,
				orgResourceType,
				org.ID,
				[]rs.GroupTraitOption{},
				rs.WithParentResourceID(resource.Id),
			)
			if err != nil {
				return nil, "", nil, fmt.Errorf("snyk-connector: failed to create org resource: %w", err)
			}
			orgResources = append(orgResources, orgResource)
		}

		// Check if there are more pages
		nextPage, err := parseLink(nextPageLink)
		if err != nil {
			// No more pages or error parsing link
			break
		}
		if nextPage == "" {
			break
		}
		pageToken = nextPage
	}

	// permission grants
	for _, member := range members {
		userID, err := rs.NewResourceID(userResourceType, member.ID)
		if err != nil {
			return nil, "", nil, fmt.Errorf("snyk-connector: failed to create user resource id: %w", err)
		}

		if slices.Contains(groupRoles, member.Role) {
			// Create the group role grant
			rv = append(rv, grant.NewGrant(resource, member.Role, userID))

			// For group admins, create "member" grants in all organizations
			// Group admins have implicit access to all orgs in the group
			if member.Role == AdminRole {
				for _, orgResource := range orgResources {
					// Create a grant with GrantImmutable annotation to mark it as immutable
					// This ensures the grant won't be updated or revoked, since group admins
					// have implicit access to all orgs (not explicit memberships in the API)
					memberGrant := grant.NewGrant(
						orgResource,
						OrgMemberEntitlement,
						userID,
						grant.WithAnnotation(&v2.GrantImmutable{}),
					)
					rv = append(rv, memberGrant)
				}
			}
		}
	}

	return rv, "", nil, nil
}

func newGroupBuilder(client *snyk.Client, id string, orgs []string) *groupBuilder {
	orgMap := make(map[string]struct{}, len(orgs))
	for _, org := range orgs {
		orgMap[org] = struct{}{}
	}

	return &groupBuilder{
		client: client,
		ID:     id,
		orgs:   orgMap,
	}
}
