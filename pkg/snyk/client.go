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
	BaseHost              = "api.snyk.io"
	Version               = "/v1"
	RestAPI               = "/rest"
	APIVersion            = "2025-11-05"
	ConductorOneUserAgent = "conductorone-snyk-1.0.0"

	GroupEndpoint         = "/group/%s"
	GroupMembersEndpoint  = "/members"
	GroupOrgsEndpoint     = "/orgs"
	GroupRolesEndpoint    = "/roles"
	OrgUserUpdateEndpoint = "/update/%s"

	OrgEndpoint        = "/org/%s"
	OrgMembersEndpoint = "/members"
	OrgInvitesEndpoint = "/invites"

	// REST API endpoints (different from v1 API).
	RestOrgEndpoint          = "/orgs/%s"
	RestGroupMembershipsPath = "groups/%s/memberships"
	RestOrgMembershipsPath   = "orgs/%s/memberships"
	RestTenantRolePath       = "tenants/%s/roles/%s"

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
// If baseURL is provided, it overrides the hostname for URL construction.
func NewClient(ctx context.Context, groupID, token string, hostname string, baseURL string) (*Client, error) {
	l := ctxzap.Extract(ctx)
	httpClient, err := uhttp.NewClient(ctx, uhttp.WithLogger(true, l))
	if err != nil {
		return nil, err
	}
	wrapper := uhttp.NewBaseHttpClient(httpClient)

	var base *url.URL
	if baseURL != "" {
		base, err = url.Parse(baseURL)
		if err != nil {
			return nil, fmt.Errorf("invalid base URL: %w", err)
		}
	} else {
		base = &url.URL{
			Scheme: "https",
			Host:   hostname,
		}
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
	u := c.baseURL.JoinPath(RestAPI, path)
	withQueryParam(u, "version", APIVersion)
	return u
}

// ListUsersInOrg retrieves all users that are members of the specified organization.
func (c *Client) ListUsersInOrg(ctx context.Context, orgID string) ([]OrgUser, error) {
	path, err := url.JoinPath("org", orgID, OrgMembersEndpoint)
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
	path, err := url.JoinPath("group", c.groupID, GroupMembersEndpoint)
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

// ListOrgMemberships returns org memberships from the REST API GET /orgs/{org_id}/memberships.
// If pageToken is provided, it should be a full URL to the next page. Otherwise, it starts from the first page.
// Returns the membership data and the Link header for pagination.
// Returns only actual org members.
func (c *Client) ListOrgMemberships(ctx context.Context, orgID string, pageToken string) (*OrgMembershipListResponse, string, error) {
	var u *url.URL
	var err error

	if pageToken != "" {
		u, err = parsePageURL(pageToken)
		if err != nil {
			return nil, "", err
		}
	} else {
		path, err := url.JoinPath("orgs", orgID, "memberships")
		if err != nil {
			return nil, "", fmt.Errorf("failed to build memberships path: %w", err)
		}
		u = c.prepareRestURL(path)
		withQueryParam(u, "limit", "100")
	}

	var response OrgMembershipListResponse
	link, err := c.getRest(ctx, u, &response, nil)
	if err != nil {
		return nil, "", err
	}

	return &response, link, nil
}

// GetGroupDetails retrieves metadata about the configured group.
func (c *Client) GetGroupDetails(ctx context.Context) (*Group, error) {
	path, err := url.JoinPath("group", c.groupID, GroupOrgsEndpoint)
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
	path, err := url.JoinPath("group", c.groupID, GroupRolesEndpoint)
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

// ListGroupServiceAccounts lists service accounts for the configured group.
// pageToken should be a full next-page URL from a previous Link header, or empty for the first page.
func (c *Client) ListGroupServiceAccounts(ctx context.Context, pageToken string) (*ServiceAccountListResponse, string, error) {
	var u *url.URL
	var err error

	if pageToken != "" {
		u, err = parsePageURL(pageToken)
		if err != nil {
			return nil, "", err
		}
	} else {
		path, err := url.JoinPath("groups", c.groupID, "service_accounts")
		if err != nil {
			return nil, "", fmt.Errorf("failed to build group service accounts path: %w", err)
		}
		u = c.prepareRestURL(path)
		withQueryParam(u, "limit", "100")
	}

	var response ServiceAccountListResponse
	link, err := c.getRest(ctx, u, &response, nil)
	if err != nil {
		return nil, "", err
	}

	return &response, link, nil
}

// ListOrgServiceAccounts lists service accounts for the given organization.
// pageToken should be a full next-page URL from a previous Link header, or empty for the first page.
func (c *Client) ListOrgServiceAccounts(ctx context.Context, orgID string, pageToken string) (*ServiceAccountListResponse, string, error) {
	var u *url.URL
	var err error

	if pageToken != "" {
		u, err = parsePageURL(pageToken)
		if err != nil {
			return nil, "", err
		}
	} else {
		path, err := url.JoinPath("orgs", orgID, "service_accounts")
		if err != nil {
			return nil, "", fmt.Errorf("failed to build org service accounts path: %w", err)
		}
		u = c.prepareRestURL(path)
		withQueryParam(u, "limit", "100")
	}

	var response ServiceAccountListResponse
	link, err := c.getRest(ctx, u, &response, nil)
	if err != nil {
		return nil, "", err
	}

	return &response, link, nil
}

// GetOrgRole retrieves a single org role by ID using the REST API.
func (c *Client) GetOrgRole(ctx context.Context, roleID string) (*Role, error) {
	path, err := url.JoinPath("tenants", c.groupID, "roles", roleID)
	if err != nil {
		return nil, fmt.Errorf("failed to build role path: %w", err)
	}
	u := c.prepareRestURL(path)

	var response RestRoleResponse
	_, err = c.getRest(ctx, u, &response, nil)
	if err != nil {
		return nil, err
	}

	role := &Role{
		ID:          response.Data.ID,
		Name:        response.Data.Attributes.Name,
		Description: response.Data.Attributes.Description,
	}
	if err := c.parseRole(role); err != nil {
		return nil, fmt.Errorf("failed to parse role: %w", err)
	}
	if role.Type != OrgRoleType {
		return nil, fmt.Errorf("role %s is not an org role (type %s)", roleID, role.Type)
	}
	return role, nil
}

// AddMemberBody represents the request body for adding a member to an organization.
type AddMemberBody struct {
	UserID string `json:"userId"`
	Role   string `json:"role"`
}

// AddOrgMember adds a user to the specified organization with the collaborator role.
func (c *Client) AddOrgMember(ctx context.Context, userID, orgID string) error {
	path, err := url.JoinPath("group", c.groupID, "org", orgID, OrgMembersEndpoint)
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
	path, err := url.JoinPath("org", orgID, OrgMembersEndpoint, userID)
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
	path, err := url.JoinPath("org", orgID, OrgMembersEndpoint, "update", userID)
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
	path, err := url.JoinPath("group", c.groupID, GroupOrgsEndpoint)
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
	path, err := url.JoinPath("orgs", orgID, OrgInvitesEndpoint)
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
	path, err := url.JoinPath("orgs", orgID, OrgInvitesEndpoint)
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

// DeleteOrgServiceAccount deletes a service account from an org via the REST API.
// See: https://apidocs.snyk.io/?version=2025-11-05#delete-/orgs/-org_id-/service_accounts/-serviceaccount_id-
func (c *Client) DeleteOrgServiceAccount(ctx context.Context, orgID, serviceAccountID string) error {
	path, err := url.JoinPath("orgs", orgID, "service_accounts", serviceAccountID)
	if err != nil {
		return fmt.Errorf("failed to build service account path: %w", err)
	}

	_, err = c.deleteRest(ctx, c.prepareRestURL(path))
	return err
}

// DeleteInvite cancels/deletes an invitation by its ID.
func (c *Client) DeleteInvite(ctx context.Context, orgID, inviteID string) error {
	path, err := url.JoinPath("orgs", orgID, OrgInvitesEndpoint, inviteID)
	if err != nil {
		return fmt.Errorf("failed to build invite path: %w", err)
	}

	_, err = c.deleteRest(ctx, c.prepareRestURL(path))
	return err
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
	applyVars(urlAddress, vars)

	opts := []uhttp.RequestOption{
		uhttp.WithAcceptJSONHeader(),
		uhttp.WithHeader("Authorization", fmt.Sprintf("token %s", c.token)),
		uhttp.WithHeader("User-Agent", ConductorOneUserAgent),
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
	applyVars(urlAddress, vars)

	opts := []uhttp.RequestOption{
		uhttp.WithHeader("Authorization", fmt.Sprintf("token %s", c.token)),
		uhttp.WithHeader("Accept", "application/vnd.api+json"),
		uhttp.WithHeader("User-Agent", ConductorOneUserAgent),
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
