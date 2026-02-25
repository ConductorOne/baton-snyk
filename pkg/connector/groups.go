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
			&v2.ChildResourceType{ResourceTypeId: serviceAccountResourceType.Id},
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
		return nil, "", nil, fmt.Errorf("snyk-connector: failed to get group details: %w", err)
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
			ent.WithGrantableTo(userResourceType, serviceAccountResourceType),
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

	// Build an authoritative set of group SA IDs from the REST API.
	// The v1 members endpoint returns both group SAs and org SAs (email == "").
	// We discriminate by the "level" field: only "Group" SAs get group role grants.
	groupSAIDs := make(map[string]struct{})
	saPageToken := ""
	for {
		select {
		case <-ctx.Done():
			return nil, "", nil, ctx.Err()
		default:
		}

		saResp, saLink, err := g.client.ListGroupServiceAccounts(ctx, saPageToken)
		if err != nil {
			return nil, "", nil, fmt.Errorf("snyk-connector: failed to list group service accounts: %w", err)
		}
		for _, sa := range saResp.Data {
			if sa.Attributes.Level == "Group" {
				groupSAIDs[sa.ID] = struct{}{}
			}
		}
		saPageToken = parseRestNextLink(saLink)
		if saPageToken == "" {
			break
		}
	}

	groupAdminEntID := fmt.Sprintf("%s:%s:%s", groupResourceType.Id, resource.Id.Resource, AdminRole)

	// Emit group role grants and collect admin principal IDs for org expansion.
	// Admins are few relative to orgs, so buffering their IDs is safe.
	var adminPrincipals []*v2.ResourceId
	for _, member := range members {
		select {
		case <-ctx.Done():
			return nil, "", nil, ctx.Err()
		default:
		}

		if member.Email == "" {
			// Only emit grants for actual group SAs; org SAs also appear in this endpoint.
			if _, isGroupSA := groupSAIDs[member.ID]; !isGroupSA {
				continue
			}
			// Service account: emit group role grant directly from the resolved slug.
			if !slices.Contains(groupRoles, member.Role) {
				continue
			}
			saIDRes, err := rs.NewResourceID(serviceAccountResourceType, member.ID)
			if err != nil {
				return nil, "", nil, fmt.Errorf("snyk-connector: failed to create service account resource id: %w", err)
			}
			rv = append(rv, grant.NewGrant(resource, member.Role, saIDRes))
			if member.Role == AdminRole {
				adminPrincipals = append(adminPrincipals, saIDRes)
			}
			continue
		}

		userID, err := rs.NewResourceID(userResourceType, member.ID)
		if err != nil {
			return nil, "", nil, fmt.Errorf("snyk-connector: failed to create user resource id: %w", err)
		}

		if !slices.Contains(groupRoles, member.Role) {
			continue
		}

		rv = append(rv, grant.NewGrant(resource, member.Role, userID))

		if member.Role == AdminRole {
			adminPrincipals = append(adminPrincipals, userID)
		}
	}

	pageToken := ""
	for {
		select {
		case <-ctx.Done():
			return nil, "", nil, ctx.Err()
		default:
		}

		orgs, nextPageLink, err := g.client.ListOrgs(ctx, snyk.NewPaginationVars(pageToken, ResourcesPageSize))
		if err != nil {
			return nil, "", nil, fmt.Errorf("snyk-connector: failed to list orgs: %w", err)
		}

		for _, org := range orgs {
			if _, ok := g.orgs[org.ID]; !ok && len(g.orgs) > 0 {
				continue
			}
			orgRes, err := rs.NewGroupResource(
				org.Name,
				orgResourceType,
				org.ID,
				[]rs.GroupTraitOption{},
				rs.WithParentResourceID(resource.Id),
			)
			if err != nil {
				return nil, "", nil, fmt.Errorf("snyk-connector: failed to create org resource: %w", err)
			}

			for _, principalID := range adminPrincipals {
				select {
				case <-ctx.Done():
					return nil, "", nil, ctx.Err()
				default:
				}
				orgGrant := grant.NewGrant(
					orgRes,
					OrgMemberEntitlement,
					principalID,
					grant.WithAnnotation(&v2.GrantImmutable{}),
				)
				orgGrant.SetSources(v2.GrantSources_builder{
					Sources: map[string]*v2.GrantSources_GrantSource{
						groupAdminEntID: {IsDirect: true},
					},
				}.Build())
				rv = append(rv, orgGrant)
			}
		}

		nextPage, err := parseLink(nextPageLink)
		if err != nil {
			if err.Error() != "no next link found in header" {
				return nil, "", nil, fmt.Errorf("snyk-connector: failed to parse pagination link: %w", err)
			}
			break
		}
		if nextPage == "" {
			break
		}
		pageToken = nextPage
	}

	return rv, "", nil, nil
}

func newGroupBuilder(client *snyk.Client, orgs []string) *groupBuilder {
	orgMap := make(map[string]struct{}, len(orgs))
	for _, org := range orgs {
		orgMap[org] = struct{}{}
	}

	return &groupBuilder{
		client: client,
		orgs:   orgMap,
	}
}
