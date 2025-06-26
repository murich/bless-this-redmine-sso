namespace :redmine do
  namespace :bless_this_sso do
    desc "Install and configure OAuth SSO plugin"
    task :install => :environment do
      puts "Installing OAuth SSO plugin..."
      
      # Ensure plugin is registered
      unless Setting.available_settings.key?('plugin_bless_this_redmine_sso')
        puts "ERROR: Plugin not properly loaded. Please restart Redmine and try again."
        exit 1
      end
      
      puts "✓ Plugin successfully loaded"
      puts "✓ OAuth SSO plugin installation complete"
      puts ""
      puts "Next steps:"
      puts "1. Configure OAuth provider: rake redmine:bless_this_sso:configure"
      puts "2. Enable SSO-only mode: rake redmine:bless_this_sso:enable_sso_only"
      puts "3. Test configuration: rake redmine:bless_this_sso:test"
    end

    desc "Configure OAuth SSO for Casdoor (or custom provider)"
    task :configure => :environment do
      puts "Configuring OAuth SSO plugin..."
      
      # Get configuration from environment or prompt
      provider_name = ENV['OAUTH_PROVIDER_NAME'] || 'Casdoor SSO'
      client_id = ENV['OAUTH_CLIENT_ID'] || 'redmine-client-id'
      client_secret = ENV['OAUTH_CLIENT_SECRET'] || 'redmine-client-secret-12345678'
      
      # Default Casdoor URLs (can be overridden via ENV)
      authorize_url = ENV['OAUTH_AUTHORIZE_URL'] || 'http://localhost:8082/login/oauth/authorize'
      token_url = ENV['OAUTH_TOKEN_URL'] || 'http://casdoor_app:8000/api/login/oauth/access_token'
      userinfo_url = ENV['OAUTH_USERINFO_URL'] || 'http://casdoor_app:8000/api/get-account'
      scope = ENV['OAUTH_SCOPE'] || 'openid email profile'
      redirect_uri = ENV['OAUTH_REDIRECT_URI'] || ''
      
      settings = {
        'oauth_enabled' => 'true',
        'oauth_sso_only' => 'false',
        'oauth_provider_name' => provider_name,
        'oauth_client_id' => client_id,
        'oauth_client_secret' => client_secret,
        'oauth_authorize_url' => authorize_url,
        'oauth_token_url' => token_url,
        'oauth_userinfo_url' => userinfo_url,
        'oauth_scope' => scope,
        'oauth_redirect_uri' => redirect_uri
      }
      
      # Save settings
      Setting.plugin_bless_this_redmine_sso = settings
      
      puts "✓ OAuth SSO configured successfully"
      puts ""
      puts "Configuration:"
      puts "  Provider Name: #{provider_name}"
      puts "  Client ID: #{client_id}"
      puts "  Authorization URL: #{authorize_url}"
      puts "  Token URL: #{token_url}"
      puts "  User Info URL: #{userinfo_url}"
      puts "  Scope: #{scope}"
      puts "  Redirect URI: #{redirect_uri.empty? ? 'Auto-generated' : redirect_uri}"
      puts ""
      puts "OAuth SSO is now enabled. Test at: /oauth/authorize"
      puts "To enable SSO-only mode: rake redmine:bless_this_sso:enable_sso_only"
    end

    desc "Enable SSO-only mode (disable username/password login)"
    task :enable_sso_only => :environment do
      puts "Enabling SSO-only mode..."
      
      current_settings = Setting.plugin_bless_this_redmine_sso || {}
      
      unless current_settings['oauth_enabled'] == 'true'
        puts "ERROR: OAuth SSO must be configured first. Run: rake redmine:bless_this_sso:configure"
        exit 1
      end
      
      current_settings['oauth_sso_only'] = 'true'
      Setting.plugin_bless_this_redmine_sso = current_settings
      
      puts "✓ SSO-only mode enabled"
      puts ""
      puts "⚠️  WARNING: Username/password login is now disabled!"
      puts "   If OAuth fails, disable SSO-only mode via rake command:"
      puts "   rake redmine:bless_this_sso:disable_sso_only"
      puts "   Or via database if rake is unavailable:"
      puts "   UPDATE settings SET value = REPLACE(value, '\"oauth_sso_only\":\"true\"', '\"oauth_sso_only\":\"false\"') WHERE name = 'plugin_bless_this_redmine_sso';"
      puts ""
      puts "All login attempts will now redirect to your OAuth provider."
    end

    desc "Disable SSO-only mode (re-enable username/password login)"
    task :disable_sso_only => :environment do
      puts "Disabling SSO-only mode..."
      
      current_settings = Setting.plugin_bless_this_redmine_sso || {}
      current_settings['oauth_sso_only'] = 'false'
      Setting.plugin_bless_this_redmine_sso = current_settings
      
      puts "✓ SSO-only mode disabled"
      puts "✓ Username/password login re-enabled"
      puts "✓ OAuth SSO remains available as alternative login method"
    end

    desc "Show current OAuth SSO configuration"
    task :status => :environment do
      puts "OAuth SSO Plugin Status"
      puts "======================="
      
      settings = Setting.plugin_bless_this_redmine_sso || {}
      
      if settings.empty?
        puts "❌ Plugin not configured"
        puts "   Run: rake redmine:bless_this_sso:configure"
        exit 0
      end
      
      enabled = settings['oauth_enabled'] == 'true'
      sso_only = settings['oauth_sso_only'] == 'true'
      
      puts "Status: #{enabled ? '✓ Enabled' : '❌ Disabled'}"
      puts "SSO-Only Mode: #{sso_only ? '✓ Enabled' : '❌ Disabled'}"
      puts ""
      puts "Configuration:"
      puts "  Provider Name: #{settings['oauth_provider_name']}"
      puts "  Client ID: #{settings['oauth_client_id']}"
      puts "  Authorization URL: #{settings['oauth_authorize_url']}"
      puts "  Token URL: #{settings['oauth_token_url']}"
      puts "  User Info URL: #{settings['oauth_userinfo_url']}"
      puts "  Scope: #{settings['oauth_scope']}"
      puts "  Redirect URI: #{settings['oauth_redirect_uri'].empty? ? 'Auto-generated' : settings['oauth_redirect_uri']}"
      puts ""
      
      if enabled
        puts "OAuth endpoints:"
        puts "  Login: /oauth/authorize"
        puts "  Callback: /oauth/callback"
        
        if sso_only
          puts ""
          puts "⚠️  SSO-Only mode active - all logins redirect to OAuth provider"
        end
      end
    end

    desc "Test OAuth SSO configuration"
    task :test => :environment do
      puts "Testing OAuth SSO configuration..."
      
      settings = Setting.plugin_bless_this_redmine_sso || {}
      
      unless settings['oauth_enabled'] == 'true'
        puts "❌ OAuth SSO not enabled"
        exit 1
      end
      
      # Test required settings
      required_settings = %w[oauth_client_id oauth_client_secret oauth_authorize_url oauth_token_url oauth_userinfo_url]
      missing_settings = required_settings.select { |setting| settings[setting].blank? }
      
      if missing_settings.any?
        puts "❌ Missing required settings: #{missing_settings.join(', ')}"
        exit 1
      end
      
      # Test URL accessibility (basic format check)
      urls_to_test = {
        'Authorization URL' => settings['oauth_authorize_url'],
        'Token URL' => settings['oauth_token_url'],
        'User Info URL' => settings['oauth_userinfo_url']
      }
      
      urls_to_test.each do |name, url|
        begin
          uri = URI.parse(url)
          puts "✓ #{name}: #{url} (format valid)"
        rescue URI::InvalidURIError
          puts "❌ #{name}: #{url} (invalid URL format)"
        end
      end
      
      puts ""
      puts "✓ Configuration test complete"
      puts "✓ All required settings present"
      puts ""
      puts "Manual test: Visit /oauth/authorize to test OAuth flow"
    end

    desc "Reset OAuth SSO configuration"
    task :reset => :environment do
      puts "Resetting OAuth SSO configuration..."
      
      Setting.plugin_bless_this_redmine_sso = {}
      
      puts "✓ OAuth SSO configuration reset"
      puts "✓ Plugin disabled"
      puts ""
      puts "To reconfigure: rake redmine:bless_this_sso:configure"
    end

    desc "Show available OAuth SSO rake tasks"
    task :help do
      puts "Available OAuth SSO rake tasks:"
      puts "==============================="
      puts ""
      puts "Setup tasks:"
      puts "  rake redmine:bless_this_sso:install     - Install plugin (check status)"
      puts "  rake redmine:bless_this_sso:configure   - Configure OAuth provider"
      puts "  rake redmine:bless_this_sso:test        - Test configuration"
      puts ""
      puts "Management tasks:"
      puts "  rake redmine:bless_this_sso:status      - Show current configuration"
      puts "  rake redmine:bless_this_sso:enable_sso_only  - Enable SSO-only mode"
      puts "  rake redmine:bless_this_sso:disable_sso_only - Disable SSO-only mode"
      puts "  rake redmine:bless_this_sso:reset       - Reset configuration"
      puts ""
      puts "Environment variables for configuration:"
      puts "  OAUTH_PROVIDER_NAME     - Display name (default: Casdoor SSO)"
      puts "  OAUTH_CLIENT_ID         - OAuth client ID"
      puts "  OAUTH_CLIENT_SECRET     - OAuth client secret"
      puts "  OAUTH_AUTHORIZE_URL     - Authorization endpoint"
      puts "  OAUTH_TOKEN_URL         - Token exchange endpoint"
      puts "  OAUTH_USERINFO_URL      - User info endpoint"
      puts "  OAUTH_SCOPE             - OAuth scopes (default: openid email profile)"
      puts "  OAUTH_REDIRECT_URI      - Callback URL (optional, auto-generated)"
      puts ""
      puts "Example for Casdoor:"
      puts "  rake redmine:bless_this_sso:configure OAUTH_CLIENT_ID=my-client OAUTH_CLIENT_SECRET=my-secret"
    end
  end
end

# Make :help the default task
task 'redmine:bless_this_sso' => 'redmine:oauth_sso:help'