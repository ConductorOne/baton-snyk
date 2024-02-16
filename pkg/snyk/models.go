package snyk

type BaseResource struct {
	ID string `json:"id"`
}

type BaseUser struct {
	BaseResource
	Username string `json:"username"`
	Email    string `json:"email"`
	Name     string `json:"name"`
}

type OrgUser struct {
	BaseUser
	Role string `json:"role"`
}

type GroupUser struct {
	BaseUser
	Role string `json:"groupRole"`
	Orgs []struct {
		Name string `json:"name"`
		Role string `json:"role"`
	} `json:"orgs"`
}

type Org struct {
	BaseResource
	Name  string `json:"name"`
	Slug  string `json:"slug"`
	URL   string `json:"url"`
	Group *Group `json:"group"`
}

type Group struct {
	BaseResource
	Name string `json:"name"`
	URL  string `json:"url"`
}

type Role struct {
	ID          string `json:"publicId"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Created     string `json:"created"`
	Modified    string `json:"modified"`
}
