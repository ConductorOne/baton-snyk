package connector

import (
	"fmt"
	"strings"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
)

const ResourcesPageSize uint = 50

func annotationsForUserResourceType() annotations.Annotations {
	annos := annotations.Annotations{}
	annos.Update(&v2.SkipEntitlementsAndGrants{})
	return annos
}

func parsePageToken(i string, resourceID *v2.ResourceId) (*pagination.Bag, string, error) {
	b := &pagination.Bag{}
	err := b.Unmarshal(i)
	if err != nil {
		return nil, "", err
	}

	if b.Current() == nil {
		b.Push(pagination.PageState{
			ResourceTypeID: resourceID.ResourceType,
			ResourceID:     resourceID.Resource,
		})
	}

	return b, b.PageToken(), nil
}

// parseLink returns parsed header representing next page in paginated response.
func parseLink(link string) (string, error) {
	parts := strings.Split(link, ";")
	url := strings.Trim(parts[0], "<>")

	for _, part := range parts[1:] {
		p := strings.TrimSpace(part)
		if strings.HasPrefix(p, "rel=") {
			rel := strings.TrimPrefix(p, "rel=")
			if rel == "last" {
				return "", nil
			} else if rel == "next" {
				return url, nil
			}
		}
	}

	return url, fmt.Errorf("no next link found in header")
}

func newPermissionEntitlement(resource *v2.Resource, id string, name string, entitlementOptions ...ent.EntitlementOption) *v2.Entitlement {
	entitlement := &v2.Entitlement{
		Id:          ent.NewEntitlementID(resource, id),
		DisplayName: name,
		Slug:        name,
		Purpose:     v2.Entitlement_PURPOSE_VALUE_PERMISSION,
		Resource:    resource,
	}

	for _, entitlementOption := range entitlementOptions {
		entitlementOption(entitlement)
	}
	return entitlement
}
