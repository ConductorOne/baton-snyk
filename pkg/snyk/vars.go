package snyk

import (
	"fmt"
	"net/url"
)

type Vars interface {
	Apply(params *url.Values)
}

// Pagination vars are used for paginating results from the API.
type PaginationVars struct {
	Page  string `json:"page"`
	Limit uint   `json:"limit"`
}

func NewPaginationVars(page string, limit uint) *PaginationVars {
	return &PaginationVars{
		Page:  page,
		Limit: limit,
	}
}

func (p *PaginationVars) Apply(params *url.Values) {
	if p.Limit > 0 {
		params.Add("limit", fmt.Sprintf("%d", p.Limit))
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
			"includeAdmin": "true",
		},
	}
}
