# Bless This Redmine SSO Plugin

A comprehensive OAuth/OpenID Connect SSO plugin for Redmine that supports any OAuth 2.0 provider by BlessThis.software.

## Features

- **Universal OAuth Support**: Works with any OAuth 2.0/OpenID Connect provider
- **Flexible Authentication**: Optional SSO-only mode or hybrid with username/password
- **User Provisioning**: Automatic user creation from OAuth provider data
- **Admin Configuration**: Easy setup through Redmine's admin interface
- **Security Features**: State parameter validation, secure token handling
- **MFA Bypass**: SSO logins skip Redmine's MFA prompts (configurable)
- **Provider Examples**: Pre-configured examples for popular providers

## Installation

1. Copy the plugin to your Redmine plugins directory:
   ```bash
   cd /path/to/redmine/plugins
   git clone https://github.com/murich/bless-this-redmine-sso.git bless_this_redmine_sso
   ```

2. Install plugin dependencies (if any):
   ```bash
   bundle install
   ```

3. Run plugin migrations:
   ```bash
   bundle exec rake redmine:plugins:migrate RAILS_ENV=production
   ```

4. Restart your Redmine instance

## Configuration

### Web Interface
1. Go to **Administration → Plugins → OAuth SSO Plugin → Configure**

2. Enable OAuth SSO and configure your provider settings:
   - **Provider Name**: Display name for your OAuth provider
   - **Client (application) ID**: OAuth application client identifier (called "Application (client) ID" in Microsoft Azure AD)
   - **Client Secret**: OAuth application client secret
   - **Authorization URL**: OAuth authorization endpoint
   - **Token URL**: OAuth token exchange endpoint  
   - **User Info URL**: Endpoint to retrieve user information
   - **Scope**: OAuth scopes (e.g., "openid email profile")
  - **Expected issuer**: OpenID Connect issuer URL that must match the `id_token` (leave blank to skip issuer verification)
   - **Expected client ID**: Optional audience override for the `id_token` (defaults to the OAuth client ID)
   - **JWKS URL**: Public JSON Web Key Set endpoint required to validate RS256-signed ID tokens
   - **Redirect URI**: Leave empty to auto-generate

   Any custom fields defined for Redmine users will appear below with a field to map OAuth keys. Provide a comma-separated list of keys for each custom field; leave blank to ignore it.
    - **Auto-create Users**: Automatically create Redmine accounts for new OAuth logins
    - **Update Existing Users**: Synchronize name, email, and mapped custom fields on each OAuth login (enabled by default)
    - **Match Users by Email**: Allow linking to existing accounts when emails match but logins differ (disabled by default)
    - **Bypass Redmine MFA**: Skip Redmine's MFA activation for SSO logins
    - **Default Group IDs**: Comma-separated list of group IDs added to new users
    - **Logout URL**: Optional provider logout endpoint to redirect users after Redmine logout

3. **Optional**: Enable "SSO-Only Mode" to disable username/password login

### Command Line Interface
You can also configure the plugin using rake commands:

```bash
# Configure OAuth SSO
rake redmine:bless_this_sso:configure OAUTH_CLIENT_ID=your-client-id OAUTH_CLIENT_SECRET=your-secret \
  OAUTH_EXPECTED_ISSUER=https://your-provider.example \
  OAUTH_EXPECTED_CLIENT_ID=your-audience-value \
  OAUTH_LOGOUT_URL=https://your-provider.example/logout

# Enable OAuth SSO
rake redmine:bless_this_sso:enable

# Disable OAuth SSO
rake redmine:bless_this_sso:disable

# Enable OAuth SSO
rake redmine:bless_this_sso:enable

# Disable OAuth SSO
rake redmine:bless_this_sso:disable

# Enable SSO-only mode
rake redmine:bless_this_sso:enable_sso_only

# Disable SSO-only mode
rake redmine:bless_this_sso:disable_sso_only

# Enable matching users by email
rake redmine:bless_this_sso:enable_match_by_email

# Disable matching users by email
rake redmine:bless_this_sso:disable_match_by_email

# Enable bypass of Redmine MFA
rake redmine:bless_this_sso:enable_bypass_twofa

# Disable bypass of Redmine MFA
rake redmine:bless_this_sso:disable_bypass_twofa

# Check configuration status
rake redmine:bless_this_sso:status

# Test configuration
rake redmine:bless_this_sso:test

# Validate full OAuth flow and inspect user info mapping
rake redmine:bless_this_sso:validate_flow
# copy the ?code= value from the redirect, then run:
OAUTH_CODE=YOUR_CODE rake redmine:bless_this_sso:validate_flow

# Show all available commands
rake redmine:bless_this_sso:help
```

The `validate_flow` task prints an authorization URL and walks through the full token and user info exchange. Open the URL in your browser, authenticate, then copy the `code` parameter from the provider's redirect and rerun the task with `OAUTH_CODE=<copied_code>`. The redirect URI you configured (default `http://localhost`) must be registered with your OAuth provider. The redirect page itself may fail to load; that's expected because no local server is required.

The `/oauth/authorize` and `/oauth/callback` endpoints are always available without a prior Redmine login. If OAuth SSO is disabled or misconfigured, these endpoints simply redirect back to the standard sign-in page, so disabling SSO or allowing both SSO and password logins remains safe.

When using the `configure` task you can specify a mapping preset via `OAUTH_FIELD_PRESET` (`generic`, `microsoft`, `google`) or override individual mappings with `OAUTH_LOGIN_FIELD`, `OAUTH_EMAIL_FIELD`, `OAUTH_FIRSTNAME_FIELD`, and `OAUTH_LASTNAME_FIELD`.
Additional provisioning options:

- `OAUTH_AUTO_CREATE` – set to `0` to disable automatic user creation
- `OAUTH_UPDATE_EXISTING` – set to `0` to keep existing user details (including custom fields) unchanged
- `OAUTH_MATCH_BY_EMAIL` – set to `1` to associate users by email when logins differ
- `OAUTH_BYPASS_TWOFA` – set to `0` to require Redmine MFA activation after SSO
- `OAUTH_PKCE` – set to `1` to enable PKCE code challenge and verifier
- `OAUTH_DEFAULT_GROUPS` – comma-separated group IDs assigned to new users
- `OAUTH_EXPECTED_ISSUER` – expected issuer (`iss`) value that must be present in the ID token
- `OAUTH_EXPECTED_CLIENT_ID` – override the `aud` value that must be present in the ID token (defaults to the OAuth client ID)
- `OAUTH_JWKS_URL` – JWKS endpoint used to download signing keys for RS256 validation

### ID Token Validation

When the OAuth provider returns an `id_token`, the plugin verifies the signature and the OpenID Connect claims using the [`jwt`](https://github.com/jwt/ruby-jwt) library. HMAC-signed tokens (`HS256`, `HS384`, `HS512`) are validated with the configured OAuth client secret, while RSA-signed tokens (`RS256`) are checked against the public keys served by the **JWKS URL** (or `OAUTH_JWKS_URL`) setting. When provided, the **Expected issuer** and **Expected client ID** settings must match the `iss` and `aud` claims and can also be set through the `OAUTH_EXPECTED_ISSUER` and `OAUTH_EXPECTED_CLIENT_ID` environment variables; leave them blank to skip those specific checks. If any validation step fails, the login is aborted and the user is shown an error describing the validation issue.

## Supported Providers

### Casdoor
```
Authorization URL: http://localhost:8082/login/oauth/authorize
Token URL: http://casdoor_app:8000/api/login/oauth/access_token
Expected issuer: http://casdoor_app:8000
JWKS URL: http://casdoor_app:8000/.well-known/jwks.json
User Info URL: http://casdoor_app:8000/api/get-account
Logout URL (optional): http://casdoor_app:8000/logout
Expected client ID: redmine-client-id
Scope: openid email profile
```

### Google OAuth
```
Authorization URL: https://accounts.google.com/o/oauth2/v2/auth
Token URL: https://oauth2.googleapis.com/token
Expected issuer: https://accounts.google.com
JWKS URL: https://www.googleapis.com/oauth2/v3/certs
User Info URL: https://www.googleapis.com/oauth2/v2/userinfo
Logout URL (optional): https://accounts.google.com/logout
Expected client ID: your-google-client-id
Scope: openid email profile
```

### Microsoft Azure AD
```
Authorization URL: https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize
Token URL: https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
Expected issuer: https://login.microsoftonline.com/{tenant}/v2.0
JWKS URL: https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys
User Info URL: https://graph.microsoft.com/v1.0/me
Logout URL (optional): https://login.microsoftonline.com/{tenant}/oauth2/v2.0/logout
Expected client ID: your-azure-client-id
Scope: openid email profile User.Read
```

> Hint: replace `{tenant}` with your tenant ID or `common` for multi-tenant apps.

Microsoft Azure AD requires the `User.Read` scope and administrator consent in the app registration so the plugin can access user information.

## SSO-Only Mode

When enabled, SSO-Only mode will:
- Redirect all login attempts to your OAuth provider
- Disable the username/password login form
- Show a warning about database recovery if OAuth fails

**Important**: If you can't log in through OAuth, disable SSO-only mode via rake command:
```bash
rake redmine:bless_this_sso:disable_sso_only
```

Or via database if rake is unavailable:
```sql
UPDATE settings SET value = REPLACE(value, '"oauth_sso_only":"1"', '"oauth_sso_only":"0"') WHERE name = 'plugin_redmine_oauth_sso';
```

## Two-Factor Authentication

SSO logins bypass Redmine's built-in MFA activation flow. The **Bypass Redmine MFA** option appears under the User Provisioning settings. To require Redmine MFA after SSO, disable this option in the UI or run `rake redmine:bless_this_sso:disable_bypass_twofa` (or set `OAUTH_BYPASS_TWOFA=0` when using the `configure` task).

## Logout Flow

When a user logs out of Redmine:

- The Redmine session is terminated.
- If a **Logout URL** is configured, the user is redirected there to end the session with the OAuth provider.
- Otherwise, the next `/oauth/authorize` redirect includes `prompt=login` so the provider forces reauthentication.

## User Mapping

The plugin maps OAuth user data to Redmine fields using configurable lists of JSON keys. In the plugin settings you can define comma-separated lists for each field; the first non-blank value found in the user info response is used.

A preset dropdown is available to load default mappings for common providers (Generic OpenID, Microsoft Azure AD, Google). After selecting a preset you can still adjust the fields manually. To see which keys your provider returns and how they resolve, run `rake redmine:bless_this_sso:validate_flow`.

The following settings are available (defaults shown):

- **`oauth_login_field`** – `name,preferred_username,sub,login,userPrincipalName`
- **`oauth_email_field`** – `email,mail,userPrincipalName`
- **`oauth_firstname_field`** – `given_name,firstName,first_name,givenName`
- **`oauth_lastname_field`** – `family_name,lastName,last_name,sn`

For each custom field on the Redmine user object an additional setting appears. Enter a comma-separated list of OAuth response keys; the first non-blank value populates that custom field. Leave the field blank to ignore it.

### Example: Microsoft Azure AD

For Microsoft Azure AD / Microsoft Graph the defaults already include the correct keys:

```
oauth_login_field: userPrincipalName
oauth_email_field: mail,userPrincipalName
oauth_firstname_field: givenName
oauth_lastname_field: sn,surname
```

## Security

- Uses state parameter to prevent CSRF attacks
- Validates OAuth responses before user creation
- Generates secure random passwords for OAuth users
- Logs all authentication attempts for auditing

## Troubleshooting

### OAuth Configuration Issues
1. Verify all URLs are accessible from your Redmine server
2. Check client ID and secret are correct
3. Ensure redirect URI matches exactly
4. Review Redmine logs for detailed error messages

### User Creation Problems
1. Check that required user data (email, username) is provided by OAuth
2. Verify user doesn't already exist with conflicting data
3. Ensure Redmine has permissions to create users

### SSO-Only Mode Recovery
If locked out due to SSO-only mode:
1. Use the rake command: `rake redmine:bless_this_sso:disable_sso_only`
2. Or access your Redmine database and run the SQL command shown in the admin interface
3. Restart Redmine to clear cached settings

## License

This plugin is released under the MIT License.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request
