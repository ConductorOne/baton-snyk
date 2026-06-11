package snyk

import (
	"fmt"
	"net/url"
)

// Vars is an interface for applying query parameters to API requests.
type Vars interface {
	Apply(params *url.Values)
}

// PaginationVars represents pagination parameters for API requests.
// Page represents parsed Link header from the response with the next page URL.
type PaginationVars struct {
	Page    string `json:"page"`
	PerPage uint   `json:"perPage"`
}

// NewPaginationVars creates a new PaginationVars instance.
func NewPaginationVars(page string, perPage uint) *PaginationVars {
	return &PaginationVars{
		Page:    page,
		PerPage: perPage,
	}
}

// Apply adds pagination parameters to the provided URL values.
func (p *PaginationVars) Apply(params *url.Values) {
	if p.PerPage > 0 {
		params.Set("perPage", fmt.Sprintf("%d", p.PerPage))
	}
}

// CommonVars represents arbitrary key-value query parameters.
type CommonVars struct {
	Vars map[string]string `json:"vars"`
}

// Apply adds common variables to the provided URL values.
func (c *CommonVars) Apply(params *url.Values) {
	for k, v := range c.Vars {
		params.Set(k, v)
	}
}

// WithIncludeAdminVar returns a Vars instance that includes group admins in responses.
func WithIncludeAdminVar() Vars {
	return &CommonVars{
		Vars: map[string]string{
			"includeGroupAdmins": "true",
		},
	}
}
