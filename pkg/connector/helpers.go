package connector

import (
	"strings"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	ent "github.com/conductorone/baton-sdk/pkg/types/entitlement"
)

// ResourcesPageSize defines the number of resources to fetch per page for paginated API calls.
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
	for _, part := range strings.Split(link, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		idx := strings.Index(part, ">")
		if idx < 0 {
			continue
		}

		linkURL := strings.Trim(strings.TrimSpace(part[:idx+1]), "<>")
		for _, param := range strings.Split(part[idx+1:], ";") {
			p := strings.TrimSpace(param)
			if !strings.HasPrefix(strings.ToLower(p), "rel=") {
				continue
			}
			rel := strings.Trim(strings.TrimSpace(p[len("rel="):]), `"'`)
			if rel == "next" {
				return linkURL, nil
			}
		}
	}

	return "", nil
}

// parseRestNextLink extracts the next page URL from a REST API Link header.
// Link format: <url>; rel="next", <url>; rel="last". Returns empty string if no next link.
func parseRestNextLink(linkHeader string) string {
	if linkHeader == "" {
		return ""
	}
	for _, part := range strings.Split(linkHeader, ",") {
		part = strings.TrimSpace(part)
		idx := strings.Index(part, ">")
		if idx < 0 {
			continue
		}
		linkURL := strings.TrimSpace(part[1:idx])
		rest := strings.TrimSpace(part[idx+1:])
		if strings.Contains(rest, `rel="next"`) || strings.Contains(rest, "rel=next") {
			return linkURL
		}
	}
	return ""
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
