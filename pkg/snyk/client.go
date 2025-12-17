// Package snyk implements an HTTP client that interacts with the Snyk API
// together with helper structures used by the connector builders. All requests
// are executed through the Baton SDK HTTP utilities and authenticated with a token.
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

// API endpoints and constants for the Snyk API.
const (
	BaseHost   = "api.snyk.io"
	Version    = "/v1"
	RestAPI    = "/rest"
	APIVersion = "2025-11-05"

	GroupEndpoint         = "/group/%s"
	GroupMembersEndpoint  = "/members"
	GroupOrgsEndpoint     = "/orgs"
	GroupRolesEndpoint    = "/roles"
	OrgUserUpdateEndpoint = "/update/%s"

	OrgEndpoint        = "/org/%s"
	OrgMembersEndpoint = "/members"
	OrgInvitesEndpoint = "/invites"

	// REST API endpoints (different from v1 API).
	RestOrgEndpoint = "/orgs/%s"

	CurrentUserOrgsEndpoint = "/orgs"

	OrgAdminRole        = "admin"
	OrgCollaboratorRole = "collaborator"
)

// Ptr returns a pointer to the given string.
func Ptr(s string) *string {
	return &s
}

// Client is an HTTP client for interacting with the Snyk API.
type Client struct {
	httpClient *uhttp.BaseHttpClient
	baseURL    *url.URL
	token      string
	groupID    string
}

// NewClient creates a new Snyk API client authenticated with the provided token.
func NewClient(ctx context.Context, groupID, token string, hostname string) (*Client, error) {
	l := ctxzap.Extract(ctx)
	httpClient, err := uhttp.NewClient(ctx, uhttp.WithLogger(true, l))
	if err != nil {
		return nil, err
	}
	wrapper := uhttp.NewBaseHttpClient(httpClient)

	base := &url.URL{
		Scheme: "https",
		Host:   hostname,
	}

	return &Client{
		httpClient: wrapper,
		baseURL:    base,
		token:      token,
		groupID:    groupID,
	}, nil
}

func (c *Client) prepareURL(path string) *url.URL {
	// Passing in the version separately since it encodes '/' if present in base url
	return c.baseURL.JoinPath(Version, path)
}

func (c *Client) prepareRestURL(path string) *url.URL {
	// Prepare URL for REST API endpoints
	u := c.baseURL.JoinPath(RestAPI, path)
	// Add version query parameter
	q := u.Query()
	q.Set("version", APIVersion)
	u.RawQuery = q.Encode()
	return u
}

// ListUsersInOrg retrieves all users that are members of the specified organization.
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

// ListUsersInGroup retrieves all users that are members of the configured group.
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

// GetGroupDetails retrieves metadata about the configured group.
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

// Role types in Snyk.
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

// ListOrgRoles retrieves all roles available in the organization.
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

// AddMemberBody represents the request body for adding a member to an organization.
type AddMemberBody struct {
	UserID string `json:"userId"`
	Role   string `json:"role"`
}

// AddOrgMember adds a user to the specified organization with the collaborator role.
func (c *Client) AddOrgMember(ctx context.Context, userID, orgID string) error {
	path, err := url.JoinPath(fmt.Sprintf(GroupEndpoint, c.groupID), fmt.Sprintf(OrgEndpoint, orgID), OrgMembersEndpoint)
	if err != nil {
		return err
	}

	body := &AddMemberBody{
		UserID: userID,
		Role:   OrgCollaboratorRole,
	}

	_, err = c.post(ctx, c.prepareURL(path), body)
	if err != nil {
		return err
	}

	return nil
}

// RemoveOrgMember removes a user from the specified organization.
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

// UpdateRoleBody represents the request body for updating a user's role.
type UpdateRoleBody struct {
	RoleID string `json:"rolePublicId"`
}

// UpdateOrgRole updates the role of a user within an organization.
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

// ListOrgs retrieves all organizations in the configured group, with pagination support.
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

// InviteUserToOrg invites a user to an organization via email.
func (c *Client) InviteUserToOrg(ctx context.Context, orgID, email, role string) (*InviteResponse, error) {
	path, err := url.JoinPath(fmt.Sprintf(RestOrgEndpoint, orgID), OrgInvitesEndpoint)
	if err != nil {
		return nil, err
	}

	body := &InviteRequest{
		Data: InviteData{
			Type: "org_invitation",
			Attributes: InviteAttributes{
				Email: email,
				Role:  role,
			},
		},
	}

	var response InviteResponse
	_, err = c.postRest(ctx, c.prepareRestURL(path), body, &response)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

// ListInvites retrieves all invitations for an organization.
func (c *Client) ListInvites(ctx context.Context, orgID string) ([]InviteResponseData, error) {
	path, err := url.JoinPath(fmt.Sprintf(RestOrgEndpoint, orgID), OrgInvitesEndpoint)
	if err != nil {
		return nil, err
	}

	var response InviteListResponse
	_, err = c.getRest(ctx, c.prepareRestURL(path), &response, nil)
	if err != nil {
		return nil, err
	}

	return response.Data, nil
}

// DeleteInvite cancels/deletes an invitation by its ID.
func (c *Client) DeleteInvite(ctx context.Context, inviteID string) error {
	// The delete endpoint uses the invite ID directly
	path := fmt.Sprintf("/orgs/invites/%s", inviteID)

	_, err := c.deleteRest(ctx, c.prepareRestURL(path))
	if err != nil {
		return err
	}

	return nil
}

// GetUserByID retrieves a user by their ID from the group.
func (c *Client) GetUserByID(ctx context.Context, userID string) (*GroupUser, error) {
	users, err := c.ListUsersInGroup(ctx)
	if err != nil {
		return nil, err
	}

	for _, user := range users {
		if user.ID == userID {
			return &user, nil
		}
	}

	return nil, fmt.Errorf("user with ID %s not found", userID)
}

// DeleteUser removes a user from all organizations in the group.
// Note: Snyk API doesn't have a direct delete user endpoint, so we remove them from all orgs.
func (c *Client) DeleteUser(ctx context.Context, userID string) error {
	// Get all organizations
	orgs, _, err := c.ListOrgs(ctx, NewPaginationVars("", 100))
	if err != nil {
		return fmt.Errorf("failed to list orgs: %w", err)
	}

	// Remove user from all organizations
	for _, org := range orgs {
		// Try to remove, ignore errors if user is not in org
		_ = c.RemoveOrgMember(ctx, userID, org.ID)
	}

	return nil
}

func (c *Client) get(ctx context.Context, urlAddress *url.URL, response interface{}, vars []Vars) (string, error) {
	return c.doRequest(ctx, urlAddress, http.MethodGet, nil, response, vars)
}

func (c *Client) post(ctx context.Context, urlAddress *url.URL, body interface{}) (string, error) {
	return c.doRequest(ctx, urlAddress, http.MethodPost, body, nil, nil)
}

func (c *Client) postRest(ctx context.Context, urlAddress *url.URL, body interface{}, response interface{}) (string, error) {
	return c.doRestRequest(ctx, urlAddress, http.MethodPost, body, response, nil)
}

func (c *Client) getRest(ctx context.Context, urlAddress *url.URL, response interface{}, vars []Vars) (string, error) {
	return c.doRestRequest(ctx, urlAddress, http.MethodGet, nil, response, vars)
}

func (c *Client) deleteRest(ctx context.Context, urlAddress *url.URL) (string, error) {
	return c.doRestRequest(ctx, urlAddress, http.MethodDelete, nil, nil, nil)
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

	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			logger := ctxzap.Extract(ctx)
			logger.Error("failed to close response body", zap.Error(cerr))
		}
	}()

	return resp.Header.Get("Link"), nil
}

func (c *Client) doRestRequest(ctx context.Context, urlAddress *url.URL, method string, data interface{}, response interface{}, vars []Vars) (string, error) {
	if vars != nil {
		query := url.Values{}

		for _, pgVars := range vars {
			pgVars.Apply(&query)
		}

		urlAddress.RawQuery = query.Encode()
	}

	opts := []uhttp.RequestOption{
		uhttp.WithHeader("Authorization", fmt.Sprintf("token %s", c.token)),
		uhttp.WithHeader("Accept", "application/vnd.api+json"),
	}

	if data != nil {
		opts = append(opts, uhttp.WithJSONBody(data), uhttp.WithHeader("Content-Type", "application/vnd.api+json"))
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

	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			logger := ctxzap.Extract(ctx)
			logger.Error("failed to close response body", zap.Error(cerr))
		}
	}()

	return resp.Header.Get("Link"), nil
}
