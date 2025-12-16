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

// ErrorResp represents an error response from the Snyk API.
type ErrorResp struct {
	Err string `json:"error"`
	Msg string `json:"message"`
}

// Message returns a formatted error message.
func (e *ErrorResp) Message() string {
	return fmt.Sprintf("unexpected error from snyk api: %s, %v", e.Err, e.Msg)
}
