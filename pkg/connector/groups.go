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

const (
	groupGrantPhaseSA      = "service_accounts"
	groupGrantPhaseMembers = "members"
)

type groupGrantState struct {
	Phase      string   `json:"phase"`
	PageToken  string   `json:"page_token,omitempty"`
	GroupSAIDs []string `json:"group_sa_ids,omitempty"`
}

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
func (g *groupBuilder) Grants(ctx context.Context, resource *v2.Resource, pToken *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	bag, err := pagination.GenBagFromToken[groupGrantState](pToken)
	if err != nil {
		return nil, "", nil, fmt.Errorf("snyk-connector: failed to parse group grant token: %w", err)
	}

	if bag.Current() == nil {
		bag.Push(groupGrantState{Phase: groupGrantPhaseSA})
	}

	state := bag.Current()

	switch state.Phase {
	case groupGrantPhaseSA:
		saResp, saLink, err := g.client.ListGroupServiceAccounts(ctx, state.PageToken)
		if err != nil {
			return nil, "", nil, fmt.Errorf("snyk-connector: failed to list group service accounts: %w", err)
		}

		saIDs := make([]string, len(state.GroupSAIDs), len(state.GroupSAIDs)+len(saResp.Data))
		copy(saIDs, state.GroupSAIDs)
		for _, sa := range saResp.Data {
			if sa.Attributes.Level == "Group" {
				saIDs = append(saIDs, sa.ID)
			}
		}

		bag.Pop()
		nextSAPage := parseRestNextLink(saLink)
		if nextSAPage != "" {
			bag.Push(groupGrantState{Phase: groupGrantPhaseSA, PageToken: nextSAPage, GroupSAIDs: saIDs})
		} else {
			bag.Push(groupGrantState{Phase: groupGrantPhaseMembers, GroupSAIDs: saIDs})
		}

		nextToken, err := bag.Marshal()
		if err != nil {
			return nil, "", nil, fmt.Errorf("snyk-connector: failed to marshal group grant token: %w", err)
		}
		return nil, nextToken, nil, nil

	case groupGrantPhaseMembers:
		groupSAIDsSet := make(map[string]struct{}, len(state.GroupSAIDs))
		for _, id := range state.GroupSAIDs {
			groupSAIDsSet[id] = struct{}{}
		}

		members, err := g.client.ListUsersInGroup(ctx)
		if err != nil {
			return nil, "", nil, fmt.Errorf("snyk-connector: failed to list users in group: %w", err)
		}

		var rv []*v2.Grant
		for _, member := range members {
			if _, isGroupSA := groupSAIDsSet[member.ID]; isGroupSA {
				if !slices.Contains(groupRoles, member.Role) {
					continue
				}
				saIDRes, err := rs.NewResourceID(serviceAccountResourceType, member.ID)
				if err != nil {
					return nil, "", nil, fmt.Errorf("snyk-connector: failed to create service account resource id: %w", err)
				}
				rv = append(rv, grant.NewGrant(resource, member.Role, saIDRes))
				continue
			}

			// Skip org SAs and other non-human entries that appear in the group members endpoint.
			if member.Email == "" {
				continue
			}

			if !slices.Contains(groupRoles, member.Role) {
				continue
			}
			userID, err := rs.NewResourceID(userResourceType, member.ID)
			if err != nil {
				return nil, "", nil, fmt.Errorf("snyk-connector: failed to create user resource id: %w", err)
			}
			rv = append(rv, grant.NewGrant(resource, member.Role, userID))
		}

		bag.Pop()
		nextToken, err := bag.Marshal()
		if err != nil {
			return nil, "", nil, fmt.Errorf("snyk-connector: failed to marshal group grant token: %w", err)
		}
		return rv, nextToken, nil, nil

	default:
		return nil, "", nil, fmt.Errorf("snyk-connector: unknown group grant phase: %s", state.Phase)
	}
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
