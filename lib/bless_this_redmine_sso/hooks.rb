module BlessThisRedmineSso
  class Hooks < Redmine::Hook::ViewListener
    def view_account_login_top(context = {})
        settings = Setting.plugin_bless_this_redmine_sso
        return '' unless %w[1 true].include?(settings['oauth_enabled'].to_s.downcase)

        # Don't show OAuth button if SSO-only mode is enabled (user should be redirected before seeing this)
        return '' if %w[1 true].include?(settings['oauth_sso_only'].to_s.downcase)
      
      provider_name = settings['oauth_provider_name'] || 'OAuth Provider'
      login_text = l(:label_login_with_provider, scope: :bless_this_redmine_sso, provider: h(provider_name))

      content = <<-HTML
        <div id="oauth-login" style="margin-bottom: 20px; padding: 15px; border: 1px solid #ddd; border-radius: 4px; background-color: #f9f9f9;">
          <p style="margin: 0 0 10px 0;"><strong>#{l(:label_or_login_with, scope: :bless_this_redmine_sso)}</strong></p>
          <a href="/oauth/authorize" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px; display: inline-block; font-weight: bold;">
            🔐 #{login_text}
          </a>
        </div>
      HTML
      
      content.html_safe
    end
  end
end
