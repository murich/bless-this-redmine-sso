Redmine::Plugin.register :bless_this_redmine_sso do
  name 'BlessThis Redmine SSO Plugin'
  author 'Blessthis.software'
  description 'OAuth/OpenID Connect SSO integration for Redmine with configurable providers'
    version '2.0.0'
  url 'https://blessthis.software'
  author_url 'https://blessthis.software'

  requires_redmine :version_or_higher => '5.0.0'

  settings :default => {
    'oauth_enabled' => false,
    'oauth_sso_only' => false,
    'oauth_provider_name' => 'OAuth Provider',
    'oauth_client_id' => '',
    'oauth_client_secret' => '',
    'oauth_expected_issuer' => '',
    'oauth_expected_client_id' => '',
    'oauth_jwks_url' => '',
    'oauth_authorize_url' => '',
    'oauth_token_url' => '',
    'oauth_userinfo_url' => '',
    'oauth_scope' => 'openid email profile User.Read',
    'oauth_redirect_uri' => '',
    'oauth_logout_url' => '',
    'oauth_pkce' => false,
    'oauth_bypass_twofa' => true,
    'oauth_mapping_preset' => 'generic',
    'oauth_login_field' => 'name,preferred_username,sub,login,userPrincipalName',
    'oauth_email_field' => 'email,mail,userPrincipalName',
    'oauth_firstname_field' => 'given_name,firstName,first_name,givenName',
    'oauth_lastname_field' => 'family_name,lastName,last_name,sn',
    'oauth_auto_create' => true,
    'oauth_update_existing' => true,
    'oauth_match_by_email' => false,
    'oauth_default_groups' => ''
  }, :partial => 'settings/bless_this_redmine_sso_settings'

  menu :admin_menu, :bless_this_sso, { :controller => 'settings', :action => 'plugin', :id => "bless_this_redmine_sso" }, :caption => :menu_bless_this_sso, :html => {:class => 'icon icon-user'}
end

require_relative 'lib/bless_this_redmine_sso/hooks'
require_relative 'lib/bless_this_redmine_sso/patches/account_controller_patch'
