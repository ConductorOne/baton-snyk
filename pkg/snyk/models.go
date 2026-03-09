package snyk

import "fmt"

// BaseResource represents a resource with an ID field.
type BaseResource struct {
	ID string `json:"id"`
}

// BaseUser represents a Snyk user with basic identity information.
type BaseUser struct {
	BaseResource
	Username string `json:"username"`
	Email    string `json:"email"`
	Name     string `json:"name"`
}

// OrgUser represents a user within an organization, including their role.
type OrgUser struct {
	BaseUser
	Role string `json:"role"`
}

// GroupUser represents a user within a group, including their group role and organization memberships.
type GroupUser struct {
	BaseUser
	Role string `json:"groupRole"`
	Orgs []struct {
		Name string `json:"name"`
		Role string `json:"role"`
	} `json:"orgs"`
}

// Org represents a Snyk organization.
type Org struct {
	BaseResource
	Name  string `json:"name"`
	Slug  string `json:"slug"`
	URL   string `json:"url"`
	Group *Group `json:"group"`
}

// Group represents a Snyk group that contains multiple organizations.
type Group struct {
	BaseResource
	Name string `json:"name"`
	URL  string `json:"url"`
}

// Role represents a Snyk role with permissions.
type Role struct {
	ID          string `json:"publicId"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Created     string `json:"created"`
	Modified    string `json:"modified"`
	Slug        string
	Type        string
}

// RestRoleResponse is the REST API response for GET /tenants/{tenant_id}/roles/{role_id}.
type RestRoleResponse struct {
	Data RestRoleData `json:"data"`
}

// RestRoleData is the role resource in the REST JSON:API response.
type RestRoleData struct {
	ID         string       `json:"id"`
	Type       string       `json:"type"`
	Attributes RestRoleAttr `json:"attributes"`
}

// RestRoleAttr contains the role attributes from the REST API.
type RestRoleAttr struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// ErrorResp represents an error response from the Snyk API.
type ErrorResp struct {
	Err string `json:"error"`
	Msg string `json:"message"`
}

// Message returns a formatted error message.
func (e *ErrorResp) Message() string {
	return fmt.Sprintf("unexpected error from snyk api: %s, %v", e.Err, e.Msg)
}

// InviteRequest represents the request body for inviting a user to an organization.
type InviteRequest struct {
	Data InviteData `json:"data"`
}

// InviteData contains the attributes for the invite request.
type InviteData struct {
	Type       string           `json:"type"`
	Attributes InviteAttributes `json:"attributes"`
}

// InviteAttributes contains the email and role for the invite.
type InviteAttributes struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

// InviteResponse represents the response from the invite API.
type InviteResponse struct {
	Data InviteResponseData `json:"data"`
}

// InviteResponseData contains the invite information.
type InviteResponseData struct {
	ID         string             `json:"id"`
	Type       string             `json:"type"`
	Attributes InviteResponseAttr `json:"attributes"`
}

// InviteResponseAttr contains the invite response attributes.
type InviteResponseAttr struct {
	Email    string `json:"email"`
	Role     string `json:"role"`
	IsActive bool   `json:"is_active"`
}

// InviteListResponse represents the response from listing invites.
type InviteListResponse struct {
	Data []InviteResponseData `json:"data"`
}

// OrgMembershipListResponse is the REST API response for GET /orgs/{org_id}/memberships.
// Matches the JSON: data[] of type "org_membership" with relationships org, user, role.
type OrgMembershipListResponse struct {
	Data []OrgMembershipData `json:"data"`
}

// OrgMembershipData is a single org membership (type "org_membership").
type OrgMembershipData struct {
	ID            string                     `json:"id"`
	Type          string                     `json:"type"`
	Attributes    OrgMembershipAttributes    `json:"attributes"`
	Relationships OrgMembershipRelationships `json:"relationships"`
}

// OrgMembershipAttributes has created_at.
type OrgMembershipAttributes struct {
	CreatedAt string `json:"created_at"`
}

// OrgMembershipRelationships has org, user, and role refs.
type OrgMembershipRelationships struct {
	User OrgMembershipUserRef `json:"user"`
	Role OrgMembershipRoleRef `json:"role"`
}

// OrgMembershipUserRef holds user data (id = user UUID for grants).
type OrgMembershipUserRef struct {
	Data *OrgMembershipRefData `json:"data"`
}

// OrgMembershipRoleRef holds role data (id = role publicId for permission grant).
type OrgMembershipRoleRef struct {
	Data *OrgMembershipRefData `json:"data"`
}

// OrgMembershipRefData minimal ref: id and optional attributes.
type OrgMembershipRefData struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Attributes map[string]interface{} `json:"attributes,omitempty"`
}

// ServiceAccountListResponse is the REST API response for listing service accounts.
type ServiceAccountListResponse struct {
	Data []ServiceAccountData `json:"data"`
}

// ServiceAccountData is a single service account in the REST API response.
type ServiceAccountData struct {
	ID         string              `json:"id"`
	Type       string              `json:"type"`
	Attributes ServiceAccountAttrs `json:"attributes"`
}

// ServiceAccountAttrs contains the service account attributes from the REST API.
type ServiceAccountAttrs struct {
	Name     string `json:"name"`
	AuthType string `json:"auth_type"`
	Level    string `json:"level"` // "Group" or "Org"
	RoleID   string `json:"role_id"`
}
