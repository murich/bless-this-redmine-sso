namespace :redmine do
  namespace :bless_this_sso do
    def plugin_settings
      Setting.clear_cache
      Setting.plugin_bless_this_redmine_sso || {}
    end

    def setting_enabled?(value)
      %w[1 true].include?(value.to_s.downcase)
    end

    def mapping_presets
      {
        'generic' => {
          'oauth_login_field' => 'name,preferred_username,sub,login,userPrincipalName',
          'oauth_email_field' => 'email,mail,userPrincipalName',
          'oauth_firstname_field' => 'given_name,firstName,first_name,givenName',
          'oauth_lastname_field' => 'family_name,lastName,last_name,sn'
        },
        'microsoft' => {
          'oauth_login_field' => 'userPrincipalName',
          'oauth_email_field' => 'mail,userPrincipalName',
          'oauth_firstname_field' => 'givenName',
          'oauth_lastname_field' => 'sn,surname'
        },
        'google' => {
          'oauth_login_field' => 'email',
          'oauth_email_field' => 'email',
          'oauth_firstname_field' => 'given_name',
          'oauth_lastname_field' => 'family_name'
        }
      }
    end

    def resolve_field(data, keys)
      keys.to_s.split(',').each do |k|
        v = data[k]
        return v if v && !v.to_s.strip.empty?
      end
      nil
    end

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
      logout_url = ENV['OAUTH_LOGOUT_URL'] || ''
      expected_issuer = ENV['OAUTH_EXPECTED_ISSUER'] || ''
      expected_client_id = ENV['OAUTH_EXPECTED_CLIENT_ID'] || ''
      jwks_url = ENV['OAUTH_JWKS_URL'] || ''

      update_existing = ENV['OAUTH_UPDATE_EXISTING'] || '1'
      match_by_email = ENV['OAUTH_MATCH_BY_EMAIL'] || '0'
      bypass_twofa = ENV['OAUTH_BYPASS_TWOFA'] || '1'
      pkce = ENV['OAUTH_PKCE'] || '0'

      preset = ENV['OAUTH_FIELD_PRESET'] || 'generic'
      preset_map = mapping_presets[preset] || mapping_presets['generic']
      login_field = ENV['OAUTH_LOGIN_FIELD'] || preset_map['oauth_login_field']
      email_field = ENV['OAUTH_EMAIL_FIELD'] || preset_map['oauth_email_field']
      firstname_field = ENV['OAUTH_FIRSTNAME_FIELD'] || preset_map['oauth_firstname_field']
      lastname_field = ENV['OAUTH_LASTNAME_FIELD'] || preset_map['oauth_lastname_field']
      auto_create = ENV['OAUTH_AUTO_CREATE'] || '1'
      default_groups = ENV['OAUTH_DEFAULT_GROUPS'] || ''

      settings = {
        'oauth_enabled' => '1',
        'oauth_sso_only' => '0',
        'oauth_provider_name' => provider_name,
        'oauth_client_id' => client_id,
        'oauth_client_secret' => client_secret,
        'oauth_expected_issuer' => expected_issuer,
        'oauth_expected_client_id' => expected_client_id,
        'oauth_jwks_url' => jwks_url,
        'oauth_authorize_url' => authorize_url,
        'oauth_token_url' => token_url,
        'oauth_userinfo_url' => userinfo_url,
        'oauth_scope' => scope,
        'oauth_redirect_uri' => redirect_uri,
        'oauth_logout_url' => logout_url,
        'oauth_mapping_preset' => preset,
        'oauth_login_field' => login_field,
        'oauth_email_field' => email_field,
        'oauth_firstname_field' => firstname_field,
        'oauth_lastname_field' => lastname_field,
        'oauth_auto_create' => auto_create,
        'oauth_update_existing' => update_existing,
        'oauth_match_by_email' => match_by_email,
        'oauth_bypass_twofa' => bypass_twofa,
        'oauth_pkce' => pkce,
        'oauth_default_groups' => default_groups
      }
      
      # Save settings
      Setting.plugin_bless_this_redmine_sso = settings
      Setting.clear_cache
      
      puts "✓ OAuth SSO configured successfully"
      puts ""
      puts "Configuration:"
      puts "  Provider Name: #{provider_name}"
      puts "  Client (application) ID: #{client_id}"
      puts "  Authorization URL: #{authorize_url}"
      puts "  Token URL: #{token_url}"
      puts "  User Info URL: #{userinfo_url}"
      puts "  Scope: #{scope}"
      puts "  Expected Issuer: #{expected_issuer.blank? ? 'None' : expected_issuer}"
      puts "  Expected Client ID (aud): #{expected_client_id.blank? ? client_id : expected_client_id}"
      puts "  JWKS URL: #{jwks_url.blank? ? 'None' : jwks_url}"
      puts "  Redirect URI: #{redirect_uri.empty? ? 'Auto-generated' : redirect_uri}"
      puts "  Mapping Preset: #{preset}"
      puts "  Login Field(s): #{login_field}"
      puts "  Email Field(s): #{email_field}"
      puts "  First Name Field(s): #{firstname_field}"
      puts "  Last Name Field(s): #{lastname_field}"
      puts "  Logout URL: #{logout_url.blank? ? 'None' : logout_url}"
      puts "  Auto-create Users: #{setting_enabled?(auto_create) ? 'Enabled' : 'Disabled'}"
      puts "  Update Existing Users: #{setting_enabled?(update_existing) ? 'Enabled' : 'Disabled'}"
      puts "  Match Users by Email: #{setting_enabled?(match_by_email) ? 'Enabled' : 'Disabled'}"
      puts "  Bypass Redmine MFA: #{setting_enabled?(bypass_twofa) ? 'Enabled' : 'Disabled'}"
      puts "  Use PKCE: #{setting_enabled?(pkce) ? 'Enabled' : 'Disabled'}"
      puts "  Default Groups: #{default_groups.blank? ? 'None' : default_groups}"
      puts ""
      puts "OAuth SSO is now enabled. Test at: /oauth/authorize"
      puts "To enable SSO-only mode: rake redmine:bless_this_sso:enable_sso_only"
    end

    desc "Enable OAuth SSO"
    task :enable => :environment do
      puts "Enabling OAuth SSO..."

      current_settings = plugin_settings
      current_settings['oauth_enabled'] = '1'
      Setting.plugin_bless_this_redmine_sso = current_settings
      Setting.clear_cache

      puts "✓ OAuth SSO enabled"
      Rake::Task['redmine:bless_this_sso:status'].reenable
      Rake::Task['redmine:bless_this_sso:status'].invoke
    end

    desc "Disable OAuth SSO"
    task :disable => :environment do
      puts "Disabling OAuth SSO..."

      current_settings = plugin_settings
      current_settings.delete('oauth_enabled')
      Setting.plugin_bless_this_redmine_sso = current_settings
      Setting.clear_cache

      puts "✓ OAuth SSO disabled"
      Rake::Task['redmine:bless_this_sso:status'].reenable
      Rake::Task['redmine:bless_this_sso:status'].invoke
    end

    desc "Enable SSO-only mode (disable username/password login)"
    task :enable_sso_only => :environment do
      puts "Enabling SSO-only mode..."
      
      current_settings = plugin_settings
      
      unless setting_enabled?(current_settings['oauth_enabled'])
        puts "ERROR: OAuth SSO must be configured first. Run: rake redmine:bless_this_sso:configure"
        exit 1
      end
      
      current_settings['oauth_sso_only'] = '1'
      Setting.plugin_bless_this_redmine_sso = current_settings
      Setting.clear_cache
      
      puts "✓ SSO-only mode enabled"
      puts ""
      puts "⚠️  WARNING: Username/password login is now disabled!"
      puts "   If OAuth fails, disable SSO-only mode via rake command:"
      puts "   rake redmine:bless_this_sso:disable_sso_only"
      puts "   Or via database if rake is unavailable:"
      puts "   UPDATE settings SET value = REPLACE(value, '\"oauth_sso_only\":\"1\"', '\"oauth_sso_only\":\"0\"') WHERE name = 'plugin_bless_this_redmine_sso';"
      puts ""
      puts "All login attempts will now redirect to your OAuth provider."
    end

    desc "Disable SSO-only mode (re-enable username/password login)"
    task :disable_sso_only => :environment do
      puts "Disabling SSO-only mode..."
      
      current_settings = plugin_settings
      current_settings.delete('oauth_sso_only')
      Setting.plugin_bless_this_redmine_sso = current_settings
      Setting.clear_cache
      
      puts "✓ SSO-only mode disabled"
      puts "✓ Username/password login re-enabled"
      puts "✓ OAuth SSO remains available as alternative login method"
    end

    desc "Enable matching users by email"
    task :enable_match_by_email => :environment do
      puts "Enabling match-by-email..."

      current_settings = plugin_settings
      current_settings['oauth_match_by_email'] = '1'
      Setting.plugin_bless_this_redmine_sso = current_settings
      Setting.clear_cache

      puts "✓ Match users by email enabled"
      Rake::Task['redmine:bless_this_sso:status'].reenable
      Rake::Task['redmine:bless_this_sso:status'].invoke
    end

    desc "Disable matching users by email"
    task :disable_match_by_email => :environment do
      puts "Disabling match-by-email..."

      current_settings = plugin_settings
      current_settings.delete('oauth_match_by_email')
      Setting.plugin_bless_this_redmine_sso = current_settings
      Setting.clear_cache

      puts "✓ Match users by email disabled"
      Rake::Task['redmine:bless_this_sso:status'].reenable
      Rake::Task['redmine:bless_this_sso:status'].invoke
    end

    desc "Enable bypass of Redmine two-factor activation"
    task :enable_bypass_twofa => :environment do
      puts "Enabling bypass of Redmine MFA..."

      current_settings = plugin_settings
      current_settings['oauth_bypass_twofa'] = '1'
      Setting.plugin_bless_this_redmine_sso = current_settings
      Setting.clear_cache

      puts "✓ Bypass Redmine MFA enabled"
      Rake::Task['redmine:bless_this_sso:status'].reenable
      Rake::Task['redmine:bless_this_sso:status'].invoke
    end

    desc "Disable bypass of Redmine two-factor activation"
    task :disable_bypass_twofa => :environment do
      puts "Disabling bypass of Redmine MFA..."

      current_settings = plugin_settings
      current_settings.delete('oauth_bypass_twofa')
      Setting.plugin_bless_this_redmine_sso = current_settings
      Setting.clear_cache

      puts "✓ Bypass Redmine MFA disabled"
      Rake::Task['redmine:bless_this_sso:status'].reenable
      Rake::Task['redmine:bless_this_sso:status'].invoke
    end

    desc "Enable PKCE (code challenge)"
    task :enable_pkce => :environment do
      puts "Enabling PKCE..."

      current_settings = plugin_settings
      current_settings['oauth_pkce'] = '1'
      Setting.plugin_bless_this_redmine_sso = current_settings
      Setting.clear_cache

      puts "✓ PKCE enabled"
      Rake::Task['redmine:bless_this_sso:status'].reenable
      Rake::Task['redmine:bless_this_sso:status'].invoke
    end

    desc "Disable PKCE"
    task :disable_pkce => :environment do
      puts "Disabling PKCE..."

      current_settings = plugin_settings
      current_settings.delete('oauth_pkce')
      Setting.plugin_bless_this_redmine_sso = current_settings
      Setting.clear_cache

      puts "✓ PKCE disabled"
      Rake::Task['redmine:bless_this_sso:status'].reenable
      Rake::Task['redmine:bless_this_sso:status'].invoke
    end

    desc "Show current OAuth SSO configuration"
    task :status => :environment do
      puts "OAuth SSO Plugin Status"
      puts "======================="
      
      settings = plugin_settings
      
      if settings.empty?
        puts "❌ Plugin not configured"
        puts "   Run: rake redmine:bless_this_sso:configure"
        exit 0
      end
      
      enabled = setting_enabled?(settings['oauth_enabled'])
      sso_only = setting_enabled?(settings['oauth_sso_only'])
      auto_create = setting_enabled?(settings['oauth_auto_create'])
      update_existing = setting_enabled?(settings['oauth_update_existing'])
      match_by_email = setting_enabled?(settings['oauth_match_by_email'])
      bypass_twofa = setting_enabled?(settings['oauth_bypass_twofa'])
      pkce = setting_enabled?(settings['oauth_pkce'])

      puts "Status: #{enabled ? '✓ Enabled' : '❌ Disabled'}"
      puts "SSO-Only Mode: #{sso_only ? '✓ Enabled' : '❌ Disabled'}"
      puts "Auto-create Users: #{auto_create ? '✓ Enabled' : '❌ Disabled'}"
      puts "Update Existing Users: #{update_existing ? '✓ Enabled' : '❌ Disabled'}"
      puts "Match Users by Email: #{match_by_email ? '✓ Enabled' : '❌ Disabled'}"
      puts "Bypass Redmine MFA: #{bypass_twofa ? '✓ Enabled' : '❌ Disabled'}"
      puts "Use PKCE: #{pkce ? '✓ Enabled' : '❌ Disabled'}"
      puts "Default Groups: #{settings['oauth_default_groups'].blank? ? 'None' : settings['oauth_default_groups']}"
      puts ""
      puts "Configuration:"
      puts "  Provider Name: #{settings['oauth_provider_name']}"
      puts "  Client (application) ID: #{settings['oauth_client_id']}"
      puts "  Authorization URL: #{settings['oauth_authorize_url']}"
      puts "  Token URL: #{settings['oauth_token_url']}"
      puts "  User Info URL: #{settings['oauth_userinfo_url']}"
      puts "  Scope: #{settings['oauth_scope']}"
      puts "  Expected Issuer: #{settings['oauth_expected_issuer'].blank? ? 'None' : settings['oauth_expected_issuer']}"
      puts "  Expected Client ID (aud): #{settings['oauth_expected_client_id'].blank? ? settings['oauth_client_id'] : settings['oauth_expected_client_id']}"
      puts "  JWKS URL: #{settings['oauth_jwks_url'].blank? ? 'None' : settings['oauth_jwks_url']}"
      puts "  Redirect URI: #{settings['oauth_redirect_uri'].empty? ? 'Auto-generated' : settings['oauth_redirect_uri']}"
      puts "  Logout URL: #{settings['oauth_logout_url'].blank? ? 'None' : settings['oauth_logout_url']}"
      puts "  Mapping Preset: #{settings['oauth_mapping_preset'] || 'custom'}"
      puts "  Login Field(s): #{settings['oauth_login_field']}"
      puts "  Email Field(s): #{settings['oauth_email_field']}"
      puts "  First Name Field(s): #{settings['oauth_firstname_field']}"
      puts "  Last Name Field(s): #{settings['oauth_lastname_field']}"

      custom_field_settings = settings.select { |k,_| k.start_with?('oauth_custom_field_') }
      if custom_field_settings.any?
        puts "  Custom Field Mappings:"
        custom_field_settings.each do |k,v|
          cf_id = k.sub('oauth_custom_field_','')
          cf_name = defined?(UserCustomField) ? UserCustomField.find_by(id: cf_id)&.name : nil
          label = cf_name || "ID #{cf_id}"
          puts "    #{label}: #{v}"
        end
      end

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

      puts ""
      puts "To #{enabled ? 'disable' : 'enable'} OAuth SSO: rake redmine:bless_this_sso:#{enabled ? 'disable' : 'enable'}"
    end

    desc "Test OAuth SSO configuration"
    task :test => :environment do
      puts "Testing OAuth SSO configuration..."
      
      settings = plugin_settings
      
      unless setting_enabled?(settings['oauth_enabled'])
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

    desc "Validate full OAuth flow"
    task :validate_flow => :environment do
      puts "Validating full OAuth flow..."

      settings = plugin_settings

      unless setting_enabled?(settings['oauth_enabled'])
        puts "❌ OAuth SSO not enabled"
        exit 1
      end

      required_settings = %w[oauth_client_id oauth_client_secret oauth_authorize_url oauth_token_url oauth_userinfo_url]
      missing = required_settings.select { |s| settings[s].blank? }
      if missing.any?
        puts "❌ Missing required settings: #{missing.join(', ')}"
        exit 1
      end

      require 'net/http'
      require 'uri'
      require 'json'
      require 'cgi'

      redirect_uri = settings['oauth_redirect_uri'].presence || 'http://localhost'
      auth_url = "#{settings['oauth_authorize_url']}?response_type=code&client_id=#{CGI.escape(settings['oauth_client_id'])}&redirect_uri=#{CGI.escape(redirect_uri)}"
      if settings['oauth_scope'].present?
        auth_url += "&scope=#{CGI.escape(settings['oauth_scope'])}"
      end

      code = ENV['OAUTH_CODE']
      unless code
        puts "Using redirect URI: #{redirect_uri}"
        puts "Open the following URL in your browser and authenticate:"
        puts auth_url
        puts ""
        puts "After authentication, copy the 'code' parameter from the redirected URL and rerun:"
        puts "OAUTH_CODE=YOUR_CODE bundle exec rake redmine:bless_this_sso:validate_flow"
        exit 0
      end

      uri = URI(settings['oauth_token_url'])
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == 'https'
      req = Net::HTTP::Post.new(uri)
      req.set_form_data({
        'grant_type' => 'authorization_code',
        'code' => code,
        'redirect_uri' => redirect_uri,
        'client_id' => settings['oauth_client_id'],
        'client_secret' => settings['oauth_client_secret']
      })
      res = http.request(req)
      if res.code.to_i >= 400
        puts "❌ Token request failed: HTTP #{res.code}"
        puts res.body
        exit 1
      end
      token_data = JSON.parse(res.body)
      access_token = token_data['access_token']
      unless access_token
        puts "❌ Token response missing access_token"
        puts res.body
        exit 1
      end
      puts "✓ Token obtained"

      uri = URI(settings['oauth_userinfo_url'])
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == 'https'
      req = Net::HTTP::Get.new(uri)
      req['Authorization'] = "Bearer #{access_token}"
      req['Accept'] = 'application/json'
      res = http.request(req)
      if res.code.to_i >= 400
        puts "❌ User info request failed: HTTP #{res.code}"
        puts res.body
        exit 1
      end

      data = JSON.parse(res.body)
      puts "Raw user info response:"
      puts JSON.pretty_generate(data)

      login = resolve_field(data, settings['oauth_login_field'])
      email = resolve_field(data, settings['oauth_email_field'])
      firstname = resolve_field(data, settings['oauth_firstname_field'])
      lastname = resolve_field(data, settings['oauth_lastname_field'])

      puts "\nResolved values using current mapping:"
      puts "  login: #{login.inspect}"
      puts "  email: #{email.inspect}"
      puts "  firstname: #{firstname.inspect}"
      puts "  lastname: #{lastname.inspect}"

      puts ""
      puts "Validation complete"
    end

    desc "Reset OAuth SSO configuration"
    task :reset => :environment do
      puts "Resetting OAuth SSO configuration..."
      
      Setting.plugin_bless_this_redmine_sso = {}
      Setting.clear_cache
      
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
      puts "  rake redmine:bless_this_sso:install       - Install plugin (check status)"
      puts "  rake redmine:bless_this_sso:configure     - Configure OAuth provider"
      puts "  rake redmine:bless_this_sso:test          - Test configuration"
      puts "  rake redmine:bless_this_sso:validate_flow - Validate full OAuth flow"
      puts ""
      puts "Management tasks:"
      puts "  rake redmine:bless_this_sso:status                - Show current configuration"
      puts "  rake redmine:bless_this_sso:enable                - Enable OAuth SSO"
      puts "  rake redmine:bless_this_sso:disable               - Disable OAuth SSO"
      puts "  rake redmine:bless_this_sso:enable_sso_only       - Enable SSO-only mode"
      puts "  rake redmine:bless_this_sso:disable_sso_only      - Disable SSO-only mode"
      puts "  rake redmine:bless_this_sso:enable_match_by_email - Match users by email"
      puts "  rake redmine:bless_this_sso:disable_match_by_email - Do not match by email"
      puts "  rake redmine:bless_this_sso:enable_bypass_twofa   - Skip Redmine MFA activation"
      puts "  rake redmine:bless_this_sso:disable_bypass_twofa  - Require Redmine MFA activation"
      puts "  rake redmine:bless_this_sso:enable_pkce           - Use PKCE code challenge"
      puts "  rake redmine:bless_this_sso:disable_pkce          - Do not use PKCE"
      puts "  rake redmine:bless_this_sso:reset                 - Reset configuration"
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
      puts "  OAUTH_LOGOUT_URL        - Provider logout endpoint"
      puts "  OAUTH_EXPECTED_ISSUER   - Expected `iss` claim for ID tokens"
      puts "  OAUTH_EXPECTED_CLIENT_ID  - Override expected `aud` (defaults to client ID)"
      puts "  OAUTH_JWKS_URL          - JWKS endpoint used for RS256 signature validation"
      puts "  OAUTH_FIELD_PRESET      - Mapping preset (generic, microsoft, google)"
      puts "  OAUTH_LOGIN_FIELD       - Override login mapping"
      puts "  OAUTH_EMAIL_FIELD       - Override email mapping"
      puts "  OAUTH_FIRSTNAME_FIELD   - Override first name mapping"
      puts "  OAUTH_LASTNAME_FIELD    - Override last name mapping"
      puts "  OAUTH_AUTO_CREATE       - Auto-create users (1 or 0)"
      puts "  OAUTH_UPDATE_EXISTING   - Update existing users (1 or 0)"
      puts "  OAUTH_MATCH_BY_EMAIL    - Match users by email when logins differ (1 or 0)"
      puts "  OAUTH_BYPASS_TWOFA      - Skip Redmine two-factor activation (1 or 0)"
      puts "  OAUTH_PKCE              - Use PKCE code challenge (1 or 0)"
      puts "  OAUTH_DEFAULT_GROUPS    - Default group IDs for new users"
      puts ""
      puts "Example for Casdoor:"
      puts "  rake redmine:bless_this_sso:configure OAUTH_CLIENT_ID=my-client OAUTH_CLIENT_SECRET=my-secret"
    end
  end
end

# Make :help the default task
task 'redmine:bless_this_sso' => 'redmine:bless_this_sso:help'
