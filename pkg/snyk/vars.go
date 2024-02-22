package snyk

import (
	"fmt"
	"net/url"
)

type Vars interface {
	Apply(params *url.Values)
}

// Pagination vars are used for paginating results from the API.
// Page represents parsed Link header from the response with the next page URL.
type PaginationVars struct {
	Page    string `json:"page"`
	PerPage uint   `json:"perPage"`
}

func NewPaginationVars(page string, perPage uint) *PaginationVars {
	return &PaginationVars{
		Page:    page,
		PerPage: perPage,
	}
}

func (p *PaginationVars) Apply(params *url.Values) {
	if p.PerPage > 0 {
		params.Add("perPage", fmt.Sprintf("%d", p.PerPage))
	}
}

type CommonVars struct {
	Vars map[string]string `json:"vars"`
}

func (c *CommonVars) Apply(params *url.Values) {
	for k, v := range c.Vars {
		params.Set(k, v)
	}
}

func WithIncludeAdminVar() Vars {
	return &CommonVars{
		Vars: map[string]string{
			"includeGroupAdmins": "true",
		},
	}
}
