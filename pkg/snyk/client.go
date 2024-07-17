package snyk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	BaseHost = "api.snyk.io/v1"

	GroupEndpoint         = "/group/%s"
	GroupMembersEndpoint  = "/members"
	GroupOrgsEndpoint     = "/orgs"
	GroupRolesEndpoint    = "/roles"
	OrgUserUpdateEndpoint = "/update/%s"

	OrgEndpoint        = "/org/%s"
	OrgMembersEndpoint = "/members"

	CurrentUserOrgsEndpoint = "/orgs"

	OrgAdminRole        = "admin"
	OrgCollaboratorRole = "collaborator"
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
	_, err = c.get(ctx, c.prepareURL(path), &users, []Vars{WithIncludeAdminVar()})
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
	_, err = c.get(ctx, c.prepareURL(path), &users, nil)
	if err != nil {
		return nil, err
	}

	return users, nil
}

func (c *Client) GetGroupDetails(ctx context.Context) (*Group, error) {
	path, err := url.JoinPath(fmt.Sprintf(GroupEndpoint, c.groupID), GroupOrgsEndpoint)
	if err != nil {
		return nil, err
	}

	// use the orgs endpoint to get the group details - ignoring list of orgs
	var group Group
	_, err = c.get(ctx, c.prepareURL(path), &group, nil)
	if err != nil {
		return nil, err
	}

	return &group, nil
}

const (
	OrgRoleType   = "org"
	GroupRoleType = "group"
)

// parseRole extracts the role type and slug from the role name.
func (c *Client) parseRole(role *Role) error {
	name := strings.ToLower(role.Name)

	if _, err := fmt.Sscanf(name, "%s %s", &role.Type, &role.Slug); err != nil {
		return fmt.Errorf("failed to parse role name and type for '%v': %w", name, err)
	}

	return nil
}

// filterRoles returns a list of roles that match the given role type.
// To properly filter the roles, we parse the role name to extract the role type and slug.
func (c *Client) filterRoles(roles []Role, roleType string) ([]Role, error) {
	var filteredRoles []Role
	for _, r := range roles {
		err := c.parseRole(&r) // #nosec G601
		if err != nil {
			return nil, err
		}

		if r.Type == roleType {
			filteredRoles = append(filteredRoles, r)
		}
	}

	return filteredRoles, nil
}

func (c *Client) ListOrgRoles(ctx context.Context) ([]Role, error) {
	path, err := url.JoinPath(fmt.Sprintf(GroupEndpoint, c.groupID), GroupRolesEndpoint)
	if err != nil {
		return nil, err
	}

	var roles []Role
	_, err = c.get(ctx, c.prepareURL(path), &roles, nil)
	if err != nil {
		return nil, err
	}

	// filter the roles to only include org roles
	orgRoles, err := c.filterRoles(roles, OrgRoleType)
	if err != nil {
		return nil, err
	}

	return orgRoles, nil
}

type AddMemberBody struct {
	UserId string `json:"userId"`
	Role   string `json:"role"`
}

func (c *Client) AddOrgMember(ctx context.Context, userID, orgID string) error {
	path, err := url.JoinPath(fmt.Sprintf(GroupEndpoint, c.groupID), fmt.Sprintf(OrgEndpoint, orgID), OrgMembersEndpoint)
	if err != nil {
		return err
	}

	body := &AddMemberBody{
		UserId: userID,
		Role:   OrgCollaboratorRole,
	}

	_, err = c.post(ctx, c.prepareURL(path), body)
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) RemoveOrgMember(ctx context.Context, userID, orgID string) error {
	path, err := url.JoinPath(fmt.Sprintf(OrgEndpoint, orgID), OrgMembersEndpoint, userID)
	if err != nil {
		return err
	}

	_, err = c.delete(ctx, c.prepareURL(path))
	if err != nil {
		return err
	}

	return nil
}

type UpdateRoleBody struct {
	RoleID string `json:"rolePublicId"`
}

func (c *Client) UpdateOrgRole(ctx context.Context, userID, orgID, roleID string) error {
	path, err := url.JoinPath(fmt.Sprintf(OrgEndpoint, orgID), OrgMembersEndpoint, fmt.Sprintf(OrgUserUpdateEndpoint, userID))
	if err != nil {
		return err
	}

	body := &UpdateRoleBody{
		RoleID: roleID,
	}

	_, err = c.put(ctx, c.prepareURL(path), body)
	if err != nil {
		return err
	}

	return nil
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
	link, err := c.get(ctx, urlAddress, &res, []Vars{pgVars})
	if err != nil {
		return nil, "", err
	}

	return res.Orgs, link, nil
}

func (c *Client) get(ctx context.Context, urlAddress *url.URL, response interface{}, vars []Vars) (string, error) {
	return c.doRequest(ctx, urlAddress, http.MethodGet, nil, response, vars)
}

func (c *Client) post(ctx context.Context, urlAddress *url.URL, body interface{}) (string, error) {
	return c.doRequest(ctx, urlAddress, http.MethodPost, body, nil, nil)
}

func (c *Client) put(ctx context.Context, urlAddress *url.URL, body interface{}) (string, error) {
	return c.doRequest(ctx, urlAddress, http.MethodPut, body, nil, nil)
}

func (c *Client) delete(ctx context.Context, urlAddress *url.URL) (string, error) {
	return c.doRequest(ctx, urlAddress, http.MethodDelete, nil, nil, nil)
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

func (c *Client) doRequest(ctx context.Context, urlAddress *url.URL, method string, data interface{}, response interface{}, vars []Vars) (string, error) {
	u, err := url.PathUnescape(urlAddress.String())
	if err != nil {
		return "", err
	}

	var body io.Reader
	if data != nil {
		jb, err := json.Marshal(data)
		if err != nil {
			return "", err
		}

		body = bytes.NewReader(jb)
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
