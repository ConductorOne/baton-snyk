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

const (
	AdminRole  = "admin"
	MemberRole = "member"
	ViewerRole = "viewer"
)

var groupRoles = []string{AdminRole, MemberRole, ViewerRole}

type groupBuilder struct {
	client *snyk.Client
	ID     string
}

func (g *groupBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return groupResourceType
}

func groupResource(ctx context.Context, group *snyk.Group) (*v2.Resource, error) {
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
func (g *groupBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
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

func (g *groupBuilder) Entitlements(ctx context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
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

func (g *groupBuilder) Grants(ctx context.Context, resource *v2.Resource, pToken *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	var rv []*v2.Grant

	members, err := g.client.ListUsersInGroup(ctx)
	if err != nil {
		return nil, "", nil, fmt.Errorf("snyk-connector: failed to list users in group: %w", err)
	}

	// permission grants
	for _, member := range members {
		userId, err := rs.NewResourceID(userResourceType, member.ID)
		if err != nil {
			return nil, "", nil, fmt.Errorf("snyk-connector: failed to create user resource id: %w", err)
		}

		if slices.Contains(groupRoles, member.Role) {
			rv = append(rv, grant.NewGrant(resource, member.Role, userId))
		}
	}

	return rv, "", nil, nil
}

func newGroupBuilder(client *snyk.Client, id string) *groupBuilder {
	return &groupBuilder{
		client: client,
		ID:     id,
	}
}
