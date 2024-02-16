package snyk

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	BaseHost = "snyk.io/api/v1"

	GroupEndpoint        = "/group/%s"
	GroupMembersEndpoint = "/members"
	GroupOrgsEndpoint    = "/orgs"
	GroupRolesEndpoint   = "/roles"

	OrgEndpoint        = "/org/%s"
	OrgMembersEndpoint = "/members"

	CurrentUserOrgsEndpoint = "/orgs"
)

type Client struct {
	httpClient *http.Client
	baseUrl    *url.URL
	token      string
	groupID    string
}

func NewClient(httpClient *http.Client, groupID, token string) *Client {
	base := &url.URL{
		Scheme: "https",
		Host:   BaseHost,
	}

	return &Client{
		httpClient: httpClient,
		baseUrl:    base,
		token:      token,
		groupID:    groupID,
	}
}

func (c *Client) prepareURL(path string) *url.URL {
	u := *c.baseUrl
	u.Path = path

	return &u
}

func (c *Client) ListUsersInOrg(ctx context.Context, orgID string) ([]OrgUser, error) {
	path, err := url.JoinPath(fmt.Sprintf(OrgEndpoint, orgID), OrgMembersEndpoint)
	if err != nil {
		return nil, err
	}

	var users []OrgUser
	_, err = c.Get(ctx, c.prepareURL(path), &users, []Vars{WithIncludeAdminVar()})
	if err != nil {
		return nil, err
	}

	return users, nil
}

func (c *Client) ListUsersInGroup(ctx context.Context) ([]GroupUser, error) {
	path, err := url.JoinPath(fmt.Sprintf(GroupEndpoint, c.groupID), GroupMembersEndpoint)
	if err != nil {
		return nil, err
	}

	var users []GroupUser
	_, err = c.Get(ctx, c.prepareURL(path), &users, nil)
	if err != nil {
		return nil, err
	}

	return users, nil
}

func (c *Client) ListOrgs(ctx context.Context, pgVars *PaginationVars) ([]Org, string, error) {
	path, err := url.JoinPath(fmt.Sprintf(GroupEndpoint, c.groupID), GroupOrgsEndpoint)
	if err != nil {
		return nil, "", err
	}

	var urlAddress *url.URL
	if pgVars.Page != "" {
		// use url from Link header if specified
		urlAddress, err = url.Parse(pgVars.Page)
		if err != nil {
			return nil, "", err
		}
	} else {
		urlAddress = c.prepareURL(path)
	}

	var res struct {
		Orgs []Org `json:"orgs"`
	}
	link, err := c.Get(ctx, urlAddress, &res, []Vars{pgVars})
	if err != nil {
		return nil, "", err
	}

	return res.Orgs, link, nil
}

func (c *Client) Get(ctx context.Context, urlAddress *url.URL, response interface{}, vars []Vars) (string, error) {
	return c.doRequest(ctx, urlAddress, http.MethodGet, nil, response, vars)
}

func (c *Client) Put(ctx context.Context, urlAddress *url.URL, body io.Reader, response interface{}, vars []Vars) (string, error) {
	return c.doRequest(ctx, urlAddress, http.MethodPut, body, response, vars)
}

func checkContentType(contentType string) error {
	if !strings.HasPrefix(contentType, "application") {
		return fmt.Errorf("unexpected content type %s", contentType)
	}

	if !strings.Contains(contentType, "json") {
		return fmt.Errorf("unexpected content type %s", contentType)
	}

	return nil
}

func parseJSON(body io.Reader, contentType string, res interface{}) error {
	if err := checkContentType(contentType); err != nil {
		r, rerr := io.ReadAll(body)
		if rerr != nil {
			return fmt.Errorf("%w - error reading response body: %w", err, rerr)
		}

		return fmt.Errorf("%w - %v", err, string(r))
	}

	if err := json.NewDecoder(body).Decode(res); err != nil {
		return fmt.Errorf("failed to decode response body: %w", err)
	}

	return nil
}

func (c *Client) doRequest(ctx context.Context, urlAddress *url.URL, method string, body io.Reader, response interface{}, vars []Vars) (string, error) {
	u, err := url.PathUnescape(urlAddress.String())
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return "", err
	}

	if vars != nil {
		query := url.Values{}

		for _, pgVars := range vars {
			pgVars.Apply(&query)
		}

		req.URL.RawQuery = query.Encode()
	}

	req.Header.Set("Authorization", fmt.Sprintf("token %s", c.token))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	contentType := resp.Header.Get("Content-Type")

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusBadRequest {
			var res struct {
				Err     string `json:"error"`
				Message string `json:"message"`
			}

			if err := parseJSON(resp.Body, contentType, &res); err != nil {
				return "", err
			}

			return "", fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, res.Message)
		}

		return "", fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}

	if method == http.MethodGet {
		if err := parseJSON(resp.Body, contentType, response); err != nil {
			return "", err
		}
	}

	return resp.Header.Get("Link"), nil
}
