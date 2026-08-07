package connector

import (
	"context"
	"fmt"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/conductorone/baton-snyk/pkg/snyk"
	"github.com/google/uuid"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

type invitationBuilder struct {
	client *snyk.Client
	orgs   map[string]struct{}
}

func (i *invitationBuilder) ResourceType(_ context.Context) *v2.ResourceType {
	return invitationResourceType
}

func (i *invitationBuilder) CreateAccountCapabilityDetails(_ context.Context) (*v2.CredentialDetailsAccountProvisioning, annotations.Annotations, error) {
	return &v2.CredentialDetailsAccountProvisioning{
		SupportedCredentialOptions: []v2.CapabilityDetailCredentialOption{
			v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_NO_PASSWORD,
		},
		PreferredCredentialOption: v2.CapabilityDetailCredentialOption_CAPABILITY_DETAIL_CREDENTIAL_OPTION_NO_PASSWORD,
	}, nil, nil
}

func (i *invitationBuilder) CreateAccount(
	ctx context.Context,
	accountInfo *v2.AccountInfo,
	credentialOptions *v2.LocalCredentialOptions,
) (
	connectorbuilder.CreateAccountResponse,
	[]*v2.PlaintextData,
	annotations.Annotations,
	error,
) {
	l := ctxzap.Extract(ctx)
	outputAnnotations := annotations.New()

	// Extract account information
	pMap := accountInfo.Profile.AsMap()
	email, ok := pMap["email"]
	if !ok {
		return nil, nil, outputAnnotations, fmt.Errorf("missing email in account info")
	}
	emailStr, ok := email.(string)
	if !ok {
		return nil, nil, outputAnnotations, fmt.Errorf("email must be a string")
	}

	// Extract organization ID from account info
	orgID, ok := pMap["org_id"]
	if !ok {
		return nil, nil, outputAnnotations, fmt.Errorf("missing org_id in account info")
	}
	orgIDStr, ok := orgID.(string)
	if !ok {
		return nil, nil, outputAnnotations, fmt.Errorf("org_id must be a string")
	}

	// Get role ID - the API requires the role UUID, not the slug
	roles, err := i.client.ListOrgRoles(ctx)
	if err != nil {
		return nil, nil, outputAnnotations, fmt.Errorf("failed to list org roles: %w", err)
	}

	// Extract role from account info (defaults to collaborator if not provided)
	roleInput, ok := pMap["role"]
	if !ok || roleInput == nil {
		roleInput = snyk.OrgCollaboratorRole
	}
	roleInputStr, ok := roleInput.(string)
	if !ok {
		return nil, nil, outputAnnotations, fmt.Errorf("role must be a string")
	}

	// Find the role ID - check if roleInput is already a UUID or a slug
	var roleID string
	_, parseErr := uuid.Parse(roleInputStr)
	isUUID := parseErr == nil

	if isUUID {
		roleID = roleInputStr
	} else {
		found := false
		for _, role := range roles {
			if role.Slug == roleInputStr {
				roleID = role.ID
				found = true
				break
			}
		}
		if !found {
			return nil, nil, outputAnnotations, fmt.Errorf("role '%s' not found in organization", roleInputStr)
		}
	}

	// Invite user to organization with role ID
	inviteResp, err := i.client.InviteUserToOrg(ctx, orgIDStr, emailStr, roleID)
	if err != nil {
		l.Error("snyk-connector: failed to invite user to org", zap.Error(err), zap.String("org_id", orgIDStr))
		return nil, nil, outputAnnotations, fmt.Errorf("failed to invite user to organization: %w", err)
	}

	// Create invitation resource with the invitation UUID
	inviteResource, err := createInvitationResource(&inviteResp.Data, orgIDStr, nil)
	if err != nil {
		return nil, nil, outputAnnotations, fmt.Errorf("failed to create invitation resource: %w", err)
	}

	car := &v2.CreateAccountResponse_SuccessResult{
		Resource: inviteResource,
	}

	return car, nil, outputAnnotations, nil
}

// Delete implements the ResourceDeleterV2 interface - cancels/deletes an invitation.
func (i *invitationBuilder) Delete(ctx context.Context, resourceId *v2.ResourceId, parentResourceID *v2.ResourceId) (annotations.Annotations, error) {
	invitationID := resourceId.GetResource()
	if len(invitationID) == 0 {
		return nil, fmt.Errorf("missing resource ID")
	}

	if parentResourceID == nil {
		return nil, fmt.Errorf("missing parent resource ID")
	}

	// Extract orgID from parent resource
	orgID := parentResourceID.GetResource()
	if len(orgID) == 0 {
		return nil, fmt.Errorf("missing organization ID in parent resource")
	}

	l := ctxzap.Extract(ctx).With(zap.String("invitationID", invitationID), zap.String("orgID", orgID))

	outputAnnotations := annotations.New()

	// Delete the invitation
	err := i.client.DeleteInvite(ctx, orgID, invitationID)
	if err != nil {
		l.Error("snyk-connector: delete-invitation: failed to delete invitation", zap.Error(err))
		return outputAnnotations, err
	}

	return outputAnnotations, nil
}

func invitationResource(_ context.Context, invite *snyk.InviteResponseData, orgID string, parentID *v2.ResourceId) (*v2.Resource, error) {
	return createInvitationResource(invite, orgID, parentID)
}

func createInvitationResource(invite *snyk.InviteResponseData, orgID string, parentID *v2.ResourceId) (*v2.Resource, error) {
	profile := map[string]interface{}{
		"email":  invite.Attributes.Email,
		"role":   invite.Attributes.Role,
		"org_id": orgID,
		"status": "pending",
	}

	userTraitOptions := []rs.UserTraitOption{
		rs.WithEmail(invite.Attributes.Email, true),
		rs.WithUserLogin(invite.Attributes.Email),
	}

	resourceOptions := []rs.ResourceOption{}
	if parentID != nil {
		resourceOptions = append(resourceOptions, rs.WithParentResourceID(parentID))
	}
	resourceOptions = append(resourceOptions, rs.WithDescription(fmt.Sprintf("Invitation for %s with role %s in organization %s", invite.Attributes.Email, invite.Attributes.Role, orgID)))

	resource, err := rs.NewUserResource(
		fmt.Sprintf("Invitation: %s", invite.Attributes.Email),
		invitationResourceType,
		invite.ID,
		userTraitOptions,
		append(resourceOptions, rs.WithResourceProfile(profile), rs.WithResourceStatus(v2.Status_RESOURCE_STATUS_ENABLED, ""))...,
	)
	if err != nil {
		return nil, err
	}

	return resource, nil
}

// List returns all invitations from organizations as resource objects.
func (i *invitationBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, _ *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	if parentResourceID == nil {
		return nil, "", nil, nil
	}

	// Only list invitations if parent is an organization
	if parentResourceID.ResourceType != orgResourceType.Id {
		return nil, "", nil, nil
	}

	orgID := parentResourceID.Resource

	// Check if we should filter by orgs
	if len(i.orgs) > 0 {
		if _, ok := i.orgs[orgID]; !ok {
			return nil, "", nil, nil
		}
	}

	invites, err := i.client.ListInvites(ctx, orgID)
	if err != nil {
		return nil, "", nil, fmt.Errorf("snyk-connector: failed to list invitations: %w", err)
	}

	var rv []*v2.Resource
	for _, invite := range invites {
		// Skip inactive invitations (already accepted or revoked)
		if !invite.Attributes.IsActive {
			continue
		}
		inviteCopy := invite
		resource, err := invitationResource(ctx, &inviteCopy, orgID, parentResourceID)
		if err != nil {
			return nil, "", nil, fmt.Errorf("snyk-connector: failed to create invitation resource: %w", err)
		}

		rv = append(rv, resource)
	}

	return rv, "", nil, nil
}

// Entitlements is required by ResourceSyncer interface. We skip entitlements and grants for invitations.
func (i *invitationBuilder) Entitlements(_ context.Context, _ *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

// Grants is required by ResourceSyncer interface but skipped via SkipEntitlementsAndGrants annotation.
func (i *invitationBuilder) Grants(_ context.Context, _ *v2.Resource, _ *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

func newInvitationBuilder(client *snyk.Client, orgs []string) *invitationBuilder {
	orgMap := make(map[string]struct{}, len(orgs))
	for _, org := range orgs {
		orgMap[org] = struct{}{}
	}

	return &invitationBuilder{
		client: client,
		orgs:   orgMap,
	}
}
