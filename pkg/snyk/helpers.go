package snyk

import (
	"fmt"
	"net/url"
)

// withQueryParam sets a query parameter on the given URL in place.
func withQueryParam(u *url.URL, key, value string) {
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
}

func applyVars(u *url.URL, vars []Vars) {
	if vars == nil {
		return
	}

	query := u.Query()
	for _, v := range vars {
		v.Apply(&query)
	}
	u.RawQuery = query.Encode()
}

// parsePageURL parses a full next-page URL string returned in a Link header.
func parsePageURL(pageToken string) (*url.URL, error) {
	u, err := url.Parse(pageToken)
	if err != nil {
		return nil, fmt.Errorf("snyk: invalid page token: %w", err)
	}
	return u, nil
}
