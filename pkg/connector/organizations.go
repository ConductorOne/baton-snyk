package connector

import (
	"context"
	"fmt"
	"slices"
	"strings"

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

// Entitlement names for organization membership and roles.
const (
	OrgMemberEntitlement       = "member"
	OrgAdminEntitlement        = "admin"
	OrgCollaboratorEntitlement = "collaborator"
)

type orgBuilder struct {
	client *snyk.Client
	orgs   map[string]struct{}
}

func (o *orgBuilder) ResourceType(_ context.Context) *v2.ResourceType {
	return orgResourceType
}

func orgResource(_ context.Context, org *snyk.Org, parentID *v2.ResourceId) (*v2.Resource, error) {
	profile := map[string]interface{}{
		"displayName": org.Name,
		"slug":        org.Slug,
		"url":         org.URL,
	}

	options := []rs.GroupTraitOption{
		rs.WithGroupProfile(profile),
	}

	resource, err := rs.NewGroupResource(
		org.Name,
		orgResourceType,
		org.ID,
		options,
		rs.WithParentResourceID(parentID),
		rs.WithAnnotation(
			&v2.ChildResourceType{ResourceTypeId: invitationResourceType.Id},
		),
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

	nextPage, err := parseLink(nextPageLink)
	if err != nil {
		return nil, "", nil, fmt.Errorf("snyk-connector: failed to parse link: %w", err)
	}
	nextToken, err := bag.NextToken(nextPage)
	if err != nil {
		return nil, "", nil, err
	}

	return rv, nextToken, nil, nil
}

// Entitlements returns slice of membership and permission entitlements for the org.
func (o *orgBuilder) Entitlements(ctx context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var rv []*v2.Entitlement

	// membership entitlements
	assignmentOptions := []ent.EntitlementOption{
		ent.WithGrantableTo(userResourceType),
		ent.WithDisplayName(fmt.Sprintf("%s %s", resource.DisplayName, OrgMemberEntitlement)),
		ent.WithDescription(fmt.Sprintf("Member of the %s organization", resource.DisplayName)),
	}

	rv = append(rv, ent.NewAssignmentEntitlement(resource, OrgMemberEntitlement, assignmentOptions...))

	// permission entitlements - could contain custom roles
	roles, err := o.client.ListOrgRoles(ctx)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to list roles in organization: %w", err)
	}

	for _, role := range roles {
		permissionOptions := []ent.EntitlementOption{
			ent.WithGrantableTo(userResourceType),
			ent.WithDisplayName(role.Name),
			ent.WithDescription(role.Description),
		}

		rv = append(rv, newPermissionEntitlement(resource, role.ID, role.Name, permissionOptions...))
	}

	return rv, "", nil, nil
}

// Grants returns slice of membership and permission grants for the org.
// Uses REST API GET /orgs/{org_id}/memberships so only actual org members appear.
func (o *orgBuilder) Grants(ctx context.Context, resource *v2.Resource, pToken *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	var rv []*v2.Grant

	bag, page, err := parsePageToken(pToken.Token, resource.Id)
	if err != nil {
		return nil, "", nil, err
	}

	resp, link, err := o.client.ListOrgMemberships(ctx, resource.Id.Resource, page)
	if err != nil {
		return nil, "", nil, fmt.Errorf("snyk-connector: failed to list org memberships: %w", err)
	}

	for _, m := range resp.Data {
		if m.Relationships.User.Data == nil || m.Relationships.Role.Data == nil {
			l.Debug("snyk-connector: org membership missing user or role data", zap.String("membership_id", m.ID))
			continue
		}
		userIDRes, err := rs.NewResourceID(userResourceType, m.Relationships.User.Data.ID)
		if err != nil {
			return nil, "", nil, fmt.Errorf("snyk-connector: failed to create user resource id: %w", err)
		}

		// membership grant (every org member has "member")
		rv = append(rv, grant.NewGrant(resource, OrgMemberEntitlement, userIDRes))
		// permission grant (role from REST: id = role publicId)
		rv = append(rv, grant.NewGrant(resource, m.Relationships.Role.Data.ID, userIDRes))
	}

	// Parse the next page link from the Link header
	nextPageURL := parseRestNextLink(link)
	nextToken, err := bag.NextToken(nextPageURL)
	if err != nil {
		return nil, "", nil, fmt.Errorf("snyk-connector: failed to create next page token: %w", err)
	}

	return rv, nextToken, nil, nil
}

// hasExplicitOrgMembership checks if a user has an explicit membership in an organization
// by iterating through all pages of memberships. Returns true if found, false otherwise.
// Group admins appear in ListUsersInOrg but not in ListOrgMemberships, so this check
// distinguishes between explicit memberships and group admin access.
func (o *orgBuilder) hasExplicitOrgMembership(ctx context.Context, orgID, userID string) (bool, error) {
	pageToken := ""
	for {
		memberships, link, err := o.client.ListOrgMemberships(ctx, orgID, pageToken)
		if err != nil {
			return false, fmt.Errorf("snyk-connector: failed to list org memberships: %w", err)
		}
		for _, m := range memberships.Data {
			if m.Relationships.User.Data != nil && m.Relationships.User.Data.ID == userID {
				return true, nil
			}
		}
		// Check if there are more pages
		nextPageURL := parseRestNextLink(link)
		if nextPageURL == "" {
			break
		}
		pageToken = nextPageURL
	}
	return false, nil
}

func (o *orgBuilder) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	parts := strings.Split(entitlement.Id, ":")
	if len(parts) != 3 {
		return nil, fmt.Errorf("snyk-connector: invalid entitlement id: %s", entitlement.Id)
	}
	roleID := parts[2]

	if principal.Id.ResourceType != userResourceType.Id {
		l.Debug(
			"snyk-connector: only users can be granted organization entitlements",
			zap.String("principal_id", principal.Id.String()),
			zap.String("principal_type", principal.Id.ResourceType),
		)

		return nil, fmt.Errorf("snyk-connector: only users can be granted organization entitlements")
	}

	users, err := o.client.ListUsersInOrg(ctx, entitlement.Resource.Id.Resource)
	if err != nil {
		return nil, fmt.Errorf("snyk-connector: failed to list users in org: %w", err)
	}
	var currentUser *snyk.OrgUser
	for i := range users {
		if users[i].ID == principal.Id.Resource {
			currentUser = &users[i]
			break
		}
	}
	// Group admins appear in ListUsersInOrg (includeGroupAdmins) but not in ListOrgMemberships.
	// Only consider the user as having an org membership if they have an explicit membership,
	// so we don't return GrantAlreadyExists for group admins.
	if currentUser != nil {
		hasExplicitMembership, err := o.hasExplicitOrgMembership(ctx, entitlement.Resource.Id.Resource, principal.Id.Resource)
		if err != nil {
			return nil, err
		}
		if !hasExplicitMembership {
			currentUser = nil
		}
	}
	if currentUser == nil {
		err := o.client.AddOrgMember(ctx, principal.Id.Resource, entitlement.Resource.Id.Resource)
		if err != nil {
			return nil, fmt.Errorf("snyk-connector: failed to add user to org: %w", err)
		}
		if roleID != OrgMemberEntitlement {
			err = o.client.UpdateOrgRole(ctx, principal.Id.Resource, entitlement.Resource.Id.Resource, roleID)
			if err != nil {
				return nil, fmt.Errorf("snyk-connector: failed to update user role in org: %w", err)
			}
		}
		return nil, nil
	}

	// Grant membership entitlement ("member"): user is already in org, nothing to do
	if roleID == OrgMemberEntitlement {
		return annotations.New(v2.GrantAlreadyExists_builder{}.Build()), nil
	}

	// Validate role exists before UpdateOrgRole (REST API GET /tenants/{tenant_id}/roles/{role_id})
	role, err := o.client.GetOrgRole(ctx, roleID)
	if err != nil {
		return nil, fmt.Errorf("snyk-connector: role %s not found: %w", roleID, err)
	}
	// GrantAlreadyExists: user already has the requested role
	if role.Slug == currentUser.Role {
		return annotations.New(v2.GrantAlreadyExists_builder{}.Build()), nil
	}

	err = o.client.UpdateOrgRole(ctx, principal.Id.Resource, entitlement.Resource.Id.Resource, roleID)
	if err != nil {
		return nil, fmt.Errorf("snyk-connector: failed to update user role in org: %w", err)
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

	users, err := o.client.ListUsersInOrg(ctx, entitlement.Resource.Id.Resource)
	if err != nil {
		return nil, fmt.Errorf("snyk-connector: failed to list users in org: %w", err)
	}
	var currentUser *snyk.OrgUser
	for i := range users {
		if users[i].ID == principal.Id.Resource {
			currentUser = &users[i]
			break
		}
	}

	// Group admins appear in ListUsersInOrg (includeGroupAdmins) but not in ListOrgMemberships.
	// Only consider the user as having an org membership if they have an explicit membership,
	// so we don't attempt to revoke from group admins who can't have their org roles revoked.
	if currentUser != nil {
		hasExplicitMembership, err := o.hasExplicitOrgMembership(ctx, entitlement.Resource.Id.Resource, principal.Id.Resource)
		if err != nil {
			return nil, err
		}
		if !hasExplicitMembership {
			currentUser = nil
		}
	}

	// GrantAlreadyRevoked: user is not in the org, nothing to revoke
	if currentUser == nil {
		return annotations.New(v2.GrantAlreadyRevoked_builder{}.Build()), nil
	}

	parts := strings.Split(entitlement.Id, ":")
	if len(parts) != 3 {
		return nil, fmt.Errorf("snyk-connector: invalid entitlement id: %s", entitlement.Id)
	}
	roleOrMemberID := parts[2]

	// Revoking membership entitlement ("member"): remove user from org
	if roleOrMemberID == OrgMemberEntitlement {
		err := o.client.RemoveOrgMember(ctx, principal.Id.Resource, entitlement.Resource.Id.Resource)
		if err != nil {
			return nil, fmt.Errorf("snyk-connector: failed to remove user from org: %w", err)
		}
		return nil, nil
	}

	roles, err := o.client.ListOrgRoles(ctx)
	if err != nil {
		return nil, fmt.Errorf("snyk-connector: failed to list roles in org: %w", err)
	}

	// check if the role is a valid role
	rI := slices.IndexFunc(roles, func(r snyk.Role) bool {
		return r.ID == roleOrMemberID
	})
	if rI == -1 {
		return nil, fmt.Errorf("snyk-connector: role %s not found", roleOrMemberID)
	}

	// GrantAlreadyRevoked: user does not have the role we're revoking
	if currentUser.Role != roles[rI].Slug {
		return annotations.New(v2.GrantAlreadyRevoked_builder{}.Build()), nil
	}

	// find minimal default role collaborator
	cI := slices.IndexFunc(roles, func(r snyk.Role) bool {
		return r.Slug == OrgCollaboratorEntitlement
	})
	if cI == -1 {
		return nil, fmt.Errorf("snyk-connector: minimal default role %s not found", OrgCollaboratorEntitlement)
	}

	collaborator := roles[cI]
	if roleOrMemberID == collaborator.ID {
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
