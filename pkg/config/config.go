package config

import (
	"github.com/conductorone/baton-sdk/pkg/field"
	"github.com/conductorone/baton-snyk/pkg/snyk"
)

var (
	apiTokenField = field.StringField(
		"api-token",
		field.WithDisplayName("API Token"),
		field.WithDescription("API token representing user or service account, used to authenticate with Snyk API."),
		field.WithIsSecret(true),
		field.WithRequired(true),
	)
	groupIDField = field.StringField(
		"group-id",
		field.WithDisplayName("Group ID"),
		field.WithDescription("Snyk group ID to scope the synchronization."),
		field.WithRequired(true),
	)
	orgIDsField = field.StringSliceField(
		"org-ids",
		field.WithDisplayName("Organization IDs"),
		field.WithDescription("Limit syncing to specified organizations."),
		field.WithStructFieldName("OrgIDs"),
	)
	hostnameField = field.StringField(
		"hostname",
		field.WithDisplayName("Snyk instance hostname"),
		field.WithDescription(`Snyk instance region hostname (defaults to "api.snyk.io").`),
		field.WithDefaultValue(snyk.BaseHost),
	)
	enableInvitationsField = field.BoolField(
		"enable-invitations",
		field.WithDisplayName("Enable Invitations"),
		field.WithDescription("Enable invitation resource synchronization and management. Requires 'org.read', 'org.user.read', and 'org.user.invite' permissions."),
		field.WithDefaultValue(false),
	)
)

//go:generate go run ./gen

// Config defines the external configuration required to run the Snyk connector.
var Config = field.NewConfiguration(
	[]field.SchemaField{
		apiTokenField,
		groupIDField,
		orgIDsField,
		hostnameField,
		enableInvitationsField,
	},
	field.WithConnectorDisplayName("Snyk"),
	field.WithHelpUrl("/docs/baton/snyk"),
	field.WithIconUrl("/static/app-icons/snyk.svg"),
)
