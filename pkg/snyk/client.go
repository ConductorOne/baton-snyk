package snyk

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

const (
	BaseHost = "api.snyk.io"
	Version  = "/v1"

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
	httpClient *uhttp.BaseHttpClient
	baseUrl    *url.URL
	token      string
	groupID    string
}

func NewClient(ctx context.Context, groupID, token string) (*Client, error) {
	l := ctxzap.Extract(ctx)
	httpClient, err := uhttp.NewClient(ctx, uhttp.WithLogger(true, l))
	if err != nil {
		return nil, err
	}
	wrapper := uhttp.NewBaseHttpClient(httpClient)

	base := &url.URL{
		Scheme: "https",
		Host:   BaseHost,
	}

	return &Client{
		httpClient: wrapper,
		baseUrl:    base,
		token:      token,
		groupID:    groupID,
	}, nil
}

func (c *Client) prepareURL(path string) *url.URL {
	u := *c.baseUrl
	// Passing in the version separately since it encodes '/' if present in base url
	u.Path = fmt.Sprintf("%s%s", Version, path)

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
func (c *Client) filterRoles(ctx context.Context, roles []Role, roleType string) ([]Role, error) {
	l := ctxzap.Extract(ctx)
	var filteredRoles []Role
	for _, r := range roles {
		err := c.parseRole(&r) // #nosec G601
		if err != nil {
			// Snyk accounts can have role names of any kind, but org roles start with "Org "
			l.Error("filterRoles", zap.Error(err))
			continue
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
	orgRoles, err := c.filterRoles(ctx, roles, OrgRoleType)
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

func (c *Client) doRequest(ctx context.Context, urlAddress *url.URL, method string, data interface{}, response interface{}, vars []Vars) (string, error) {
	if vars != nil {
		query := url.Values{}

		for _, pgVars := range vars {
			pgVars.Apply(&query)
		}

		urlAddress.RawQuery = query.Encode()
	}

	opts := []uhttp.RequestOption{
		uhttp.WithAcceptJSONHeader(),
		uhttp.WithHeader("Authorization", fmt.Sprintf("token %s", c.token)),
	}

	if data != nil {
		opts = append(opts, uhttp.WithJSONBody(data), uhttp.WithContentTypeJSONHeader())
	}

	req, err := c.httpClient.NewRequest(ctx, method, urlAddress, opts...)
	if err != nil {
		return "", err
	}

	errResp := &ErrorResp{}
	doOpts := []uhttp.DoOption{
		uhttp.WithErrorResponse(errResp),
	}
	if response != nil {
		doOpts = append(doOpts, uhttp.WithJSONResponse(response))
	}

	resp, err := c.httpClient.Do(req, doOpts...)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	return resp.Header.Get("Link"), nil
}
