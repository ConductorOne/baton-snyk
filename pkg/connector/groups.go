package connector

import (
	"context"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/conductorone/baton-snyk/pkg/snyk"
)

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

	gr, err := groupResource(ctx, &snyk.Group{
		BaseResource: snyk.BaseResource{ID: g.ID},
	})
	if err != nil {
		return nil, "", nil, err
	}

	rv = append(rv, gr)

	return rv, "", nil, nil
}

func (g *groupBuilder) Entitlements(_ context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func (g *groupBuilder) Grants(ctx context.Context, resource *v2.Resource, pToken *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func (g *groupBuilder) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) (annotations.Annotations, error) {
	return nil, nil
}

func (g *groupBuilder) Revoke(ctx context.Context, grant *v2.Grant) (annotations.Annotations, error) {
	return nil, nil
}

func newGroupBuilder(client *snyk.Client, id string) *groupBuilder {
	return &groupBuilder{
		client: client,
		ID:     id,
	}
}
