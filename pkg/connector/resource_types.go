package connector

import (
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
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
)
