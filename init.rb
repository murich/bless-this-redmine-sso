Redmine::Plugin.register :bless_this_redmine_sso do
  name 'BlessThis Redmine SSO Plugin'
  author 'Blessthis.software'
  description 'OAuth/OpenID Connect SSO integration for Redmine with configurable providers'
  version '1.0.0'
  url 'https://blessthis.software'
  author_url 'https://blessthis.software'

  requires_redmine :version_or_higher => '5.0.0'

  settings :default => {
    'oauth_enabled' => false,
    'oauth_sso_only' => false,
    'oauth_provider_name' => 'OAuth Provider',
    'oauth_client_id' => '',
    'oauth_client_secret' => '',
    'oauth_authorize_url' => '',
    'oauth_token_url' => '',
    'oauth_userinfo_url' => '',
    'oauth_scope' => 'openid email profile',
    'oauth_redirect_uri' => ''
  }, :partial => 'settings/bless_this_redmine_sso_settings'

  menu :admin_menu, :bless_this_sso, { :controller => 'settings', :action => 'plugin', :id => "bless_this_redmine_sso" }, :caption => 'BlessThis SSO', :html => {:class => 'icon icon-user'}
end

require_relative 'lib/bless_this_redmine_sso/hooks'
require_relative 'lib/bless_this_redmine_sso/patches/account_controller_patch'