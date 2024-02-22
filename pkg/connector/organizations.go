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
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

const (
	OrgMemberEntitlement       = "member"
	OrgAdminEntitlement        = "admin"
	OrgCollaboratorEntitlement = "collaborator"
)

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
	roles, err := o.client.ListOrgRoles(ctx)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to list roles in group: %w", err)
	}

	for _, role := range roles {
		permissionOptions := []ent.EntitlementOption{
			ent.WithGrantableTo(userResourceType),
			ent.WithDisplayName(role.Name),
			ent.WithDescription(role.Description),
		}

		rv = append(rv, ent.NewPermissionEntitlement(resource, role.ID, permissionOptions...))
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

		// permission grants - require finding role public id to match with entitlement
		roles, err := o.client.ListOrgRoles(ctx)
		if err != nil {
			return nil, "", nil, fmt.Errorf("snyk-connector: failed to list roles in org: %w", err)
		}

		// check if the role is a valid role
		rI := slices.IndexFunc(roles, func(r snyk.Role) bool {
			return r.Slug == member.Role
		})

		if rI == -1 {
			return nil, "", nil, fmt.Errorf("snyk-connector: role %s not found", member.Role)
		}

		rv = append(rv, grant.NewGrant(resource, roles[rI].ID, userId))
	}

	return rv, "", nil, nil
}

func (o *orgBuilder) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	if principal.Id.ResourceType != userResourceType.Id {
		l.Debug(
			"snyk-connector: only users can be granted organization entitlements",
			zap.String("principal_id", principal.Id.String()),
			zap.String("principal_type", principal.Id.ResourceType),
		)

		return nil, fmt.Errorf("snyk-connector: only users can be granted organization entitlements")
	}

	if entitlement.Slug == OrgMemberEntitlement {
		err := o.client.AddOrgMember(ctx, principal.Id.Resource, entitlement.Resource.Id.Resource)
		if err != nil {
			return nil, fmt.Errorf("snyk-connector: failed to add user to org: %w", err)
		}

		return nil, nil
	} else {
		err := o.client.UpdateOrgRole(ctx, principal.Id.Resource, entitlement.Resource.Id.Resource, entitlement.Slug)
		if err != nil {
			return nil, fmt.Errorf("snyk-connector: failed to update user role in org: %w", err)
		}
	}

	return nil, nil
}

func (o *orgBuilder) Revoke(ctx context.Context, grant *v2.Grant) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	principal := grant.Principal
	entitlement := grant.Entitlement

	if principal.Id.ResourceType != userResourceType.Id {
		l.Debug(
			"snyk-connector: only users can have organization entitlements revoked",
			zap.String("principal_id", principal.Id.String()),
			zap.String("principal_type", principal.Id.ResourceType),
		)

		return nil, fmt.Errorf("snyk-connector: only users can have organization entitlements revoked")
	}

	if entitlement.Slug == OrgMemberEntitlement {
		err := o.client.RemoveOrgMember(ctx, principal.Id.Resource, entitlement.Resource.Id.Resource)
		if err != nil {
			return nil, fmt.Errorf("snyk-connector: failed to remove user from org: %w", err)
		}
	} else {
		rolePublicID := entitlement.Slug
		roles, err := o.client.ListOrgRoles(ctx)
		if err != nil {
			return nil, fmt.Errorf("snyk-connector: failed to list roles in org: %w", err)
		}

		// check if the role is a valid role
		rI := slices.IndexFunc(roles, func(r snyk.Role) bool {
			return r.ID == rolePublicID
		})
		if rI == -1 {
			return nil, fmt.Errorf("snyk-connector: role %s not found", rolePublicID)
		}

		// find minimal default role collaborator
		cI := slices.IndexFunc(roles, func(r snyk.Role) bool {
			return r.Slug == OrgCollaboratorEntitlement
		})
		if cI == -1 {
			return nil, fmt.Errorf("snyk-connector: minimal default role %s not found", OrgCollaboratorEntitlement)
		}

		collaborator := roles[cI]
		if rolePublicID == collaborator.ID {
			// if we're revoking collaborator role - remove from org
			err = o.client.RemoveOrgMember(ctx, principal.Id.Resource, entitlement.Resource.Id.Resource)
			if err != nil {
				return nil, fmt.Errorf("snyk-connector: failed to remove user from org: %w", err)
			}
		} else {
			// if we're revoking admin or other role - rollback to minimal role collaborator
			err = o.client.UpdateOrgRole(ctx, principal.Id.Resource, entitlement.Resource.Id.Resource, collaborator.ID)
			if err != nil {
				return nil, fmt.Errorf("snyk-connector: failed to update user role in org: %w", err)
			}
		}
	}

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
