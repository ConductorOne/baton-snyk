While developing the connector, please fill out this form. This information is needed to write docs and to help other users set up the connector.

## Connector capabilities

1. What resources does the connector sync?

- Groups
- Organizations
- Users
- Invitations (pending invitations)

2. Can the connector provision any resources? If so, which ones?

Yes, the connector can provision:
- **Invitations**: Can create invitations for users to organizations (with a specific role, default is `collaborator`)
- **Invitations**: Can delete/cancel pending invitations

## Connector credentials

1. What credentials or information are needed to set up the connector? (For example, API key, client ID and secret, domain, etc.)

- **API Token** (required): API token representing a user or service account, used to authenticate with Snyk API
- **Group ID** (required): Snyk group ID to scope the synchronization
- **Hostname** (optional): Snyk region hostname (defaults to `api.snyk.io` for region SNYK-US-01)
- **Org IDs** (optional): Comma-separated list of organization IDs to limit syncing scope
- **Enable Invitations** (optional): Enable invitation resource synchronization and management. Requires 'org.read', 'org.user.read', and 'org.user.invite' permissions (defaults to `false`)

2. For each item in the list above:

   * How does a user create or look up that credential or info? Please include links to (non-gated) documentation, screenshots (of the UI or of gated docs), or a video of the process.

   **API Token**: 
   - Navigate to your Snyk account settings
   - Generate or copy your API token from the account settings page

   **Group ID**: 
   - Can be found in the URL of the group page in the Snyk web platform (e.g., `https://app.snyk.io/group/<GROUP_ID>`)
   - Alternatively, find it in Group general settings within the Snyk UI

   **Hostname**: 
   - Depends on the region where your Snyk account is hosted
   - Default is `api.snyk.io` (SNYK-US-01)
   - For other regions, refer to: https://docs.snyk.io/snyk-api/v1-api#api-urls

   **Org IDs**: 
   - list of organization IDs to limit the synchronization scope
   - If not provided, all organizations in the group will be synced

   **Enable Invitations**: 
   - Boolean flag to enable invitation resource synchronization and management
   - Defaults to `false`
   - When enabled, requires additional API token permissions: 'org.read', 'org.user.read', and 'org.user.invite'

   * Does the credential need any specific scopes or permissions? If so, list them here.

   **API Token**: The user or service account represented by the API token must have **Group Admin** permissions in the Snyk group being synced.
   
   **Enable Invitations**: When this flag is enabled, the API token must have the following additional permissions: `org.read`, `org.user.read`, and `org.user.invite`.

   * If applicable: Is the list of scopes or permissions different to sync (read) versus provision (read-write)? If so, list the difference here.

   For basic sync operations, **Group Admin** permissions are required. When the **Enable Invitations** flag is enabled (which allows provisioning of invitations), the API token must additionally have `org.read`, `org.user.read`, and `org.user.invite` permissions.

   * What level of access or permissions does the user need in order to create the credentials? (For example, must be a super administrator, must have access to the admin console, etc.)

   The user must be a **Group Administrator** in Snyk to generate an API token with sufficient permissions for the connector to work properly.
