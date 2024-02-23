package connector

import (
	"fmt"
	"strings"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
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
