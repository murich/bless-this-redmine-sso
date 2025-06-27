# Bless This Redmine SSO Plugin

A comprehensive OAuth/OpenID Connect SSO plugin for Redmine that supports any OAuth 2.0 provider by BlessThis.software.

## Features

- **Universal OAuth Support**: Works with any OAuth 2.0/OpenID Connect provider
- **Flexible Authentication**: Optional SSO-only mode or hybrid with username/password
- **User Provisioning**: Automatic user creation from OAuth provider data
- **Admin Configuration**: Easy setup through Redmine's admin interface
- **Security Features**: State parameter validation, secure token handling
- **Provider Examples**: Pre-configured examples for popular providers

## Installation

1. Copy the plugin to your Redmine plugins directory:
   ```bash
   cd /path/to/redmine/plugins
   git clone https://github.com/murich/bless-this-redmine-sso.git
   cp -r bless_this_redmine_sso /path/to/redmine/plugins/
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
   - **Client ID**: OAuth application client ID
   - **Client Secret**: OAuth application client secret
   - **Authorization URL**: OAuth authorization endpoint
   - **Token URL**: OAuth token exchange endpoint  
   - **User Info URL**: Endpoint to retrieve user information
   - **Scope**: OAuth scopes (e.g., "openid email profile")
   - **Redirect URI**: Leave empty to auto-generate

3. **Optional**: Enable "SSO-Only Mode" to disable username/password login

### Command Line Interface
You can also configure the plugin using rake commands:

```bash
# Configure OAuth SSO
rake redmine:bless_this_sso:configure OAUTH_CLIENT_ID=your-client-id OAUTH_CLIENT_SECRET=your-secret

# Enable SSO-only mode
rake redmine:bless_this_sso:enable_sso_only

# Disable SSO-only mode
rake redmine:bless_this_sso:disable_sso_only

# Check configuration status
rake redmine:bless_this_sso:status

# Test configuration
rake redmine:bless_this_sso:test

# Show all available commands
rake redmine:bless_this_sso:help
```

## Supported Providers

### Casdoor
```
Authorization URL: http://your-casdoor:8082/login/oauth/authorize
Token URL: http://your-casdoor:8000/api/login/oauth/access_token
User Info URL: http://your-casdoor:8000/api/get-account
Scope: openid email profile
```

### Google OAuth
```
Authorization URL: https://accounts.google.com/o/oauth2/v2/auth
Token URL: https://oauth2.googleapis.com/token
User Info URL: https://www.googleapis.com/oauth2/v2/userinfo
Scope: openid email profile
```

### Microsoft Azure AD
```
Authorization URL: https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize
Token URL: https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
User Info URL: https://graph.microsoft.com/v1.0/me
Scope: openid email profile
```

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

## User Mapping

The plugin maps OAuth user data to Redmine fields:
- **Username**: `name`, `preferred_username`, `sub`, or `login`
- **Email**: `email`
- **First Name**: `given_name`, `firstName`, or `first_name`
- **Last Name**: `family_name`, `lastName`, or `last_name`

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
