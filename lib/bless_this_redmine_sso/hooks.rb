module BlessThisRedmineSso
  class Hooks < Redmine::Hook::ViewListener
    def view_account_login_top(context = {})
      settings = Setting.plugin_bless_this_redmine_sso
      return '' unless settings['oauth_enabled']
      
      # Don't show OAuth button if SSO-only mode is enabled (user should be redirected before seeing this)
      return '' if settings['oauth_sso_only']
      
      provider_name = settings['oauth_provider_name'] || 'OAuth Provider'
      
      content = <<-HTML
        <div id="oauth-login" style="margin-bottom: 20px; padding: 15px; border: 1px solid #ddd; border-radius: 4px; background-color: #f9f9f9;">
          <p style="margin: 0 0 10px 0;"><strong>Or login with:</strong></p>
          <a href="/oauth/authorize" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; display: inline-block; font-weight: bold;">
            🔐 Login with #{h(provider_name)}
          </a>
        </div>
      HTML
      
      content.html_safe
    end
  end
end