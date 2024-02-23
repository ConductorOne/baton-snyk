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

type userBuilder struct {
	client *snyk.Client
}

func (u *userBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return userResourceType
}

func userResource(ctx context.Context, user *snyk.GroupUser, parentID *v2.ResourceId) (*v2.Resource, error) {
	profile := map[string]interface{}{
		"displayName": user.Name,
		"email":       user.Email,
		"role":        user.Role,
	}

	resource, err := rs.NewUserResource(
		user.Name,
		userResourceType,
		user.ID,
		[]rs.UserTraitOption{
			rs.WithUserProfile(profile),
		},
		rs.WithParentResourceID(parentID),
	)
	if err != nil {
		return nil, err
	}

	return resource, nil
}

// List returns all the users from the database as resource objects.
func (u *userBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, _ *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	if parentResourceID == nil {
		return nil, "", nil, nil
	}

	users, err := u.client.ListUsersInGroup(ctx)
	if err != nil {
		return nil, "", nil, fmt.Errorf("snyk-connector: failed to list users: %w", err)
	}

	var rv []*v2.Resource
	for _, user := range users {
		uCopy := user
		resource, err := userResource(ctx, &uCopy, parentResourceID)
		if err != nil {
			return nil, "", nil, fmt.Errorf("snyk-connector: failed to create user resource: %w", err)
		}

		rv = append(rv, resource)
	}

	return rv, "", nil, nil
}

// Entitlements always returns an empty slice for users.
func (u *userBuilder) Entitlements(_ context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

// Grants always returns an empty slice for users since they don't have any entitlements.
func (u *userBuilder) Grants(ctx context.Context, resource *v2.Resource, pToken *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func newUserBuilder(client *snyk.Client) *userBuilder {
	return &userBuilder{
		client: client,
	}
}
