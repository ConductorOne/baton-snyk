package connector

import (
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
)

var (
	// The group resource type is for all group objects from the database.
	groupResourceType = &v2.ResourceType{
		Id:          "group",
		DisplayName: "Group",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_GROUP},
	}

	// The org resource type is for all org objects from the database.
	orgResourceType = &v2.ResourceType{
		Id:          "org",
		DisplayName: "Organization",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_GROUP},
	}

	// The user resource type is for all user objects from the database.
	userResourceType = &v2.ResourceType{
		Id:          "user",
		DisplayName: "User",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_USER},
		Annotations: annotationsForUserResourceType(),
	}

	// The invitation resource type is for all invitation objects.
	// Requires the "org.user.invite" permission for both creating and deleting invitations.
	// See: https://apidocs.snyk.io/?version=2025-11-05#post-/orgs/-org_id-/invites
	invitationResourceType = &v2.ResourceType{
		Id:          "invitation",
		DisplayName: "Invitation",
		Traits:      []v2.ResourceType_Trait{v2.ResourceType_TRAIT_USER},
		Annotations: annotations.New(&v2.CapabilityPermissions{
			Permissions: []*v2.CapabilityPermission{
				{Permission: "org.user.invite"},
			},
		}),
	}
)
