module BlessThisRedmineSso
  class Hooks < Redmine::Hook::ViewListener
    def view_account_login_top(context = {})
      settings = Setting.plugin_bless_this_redmine_sso
      return '' unless %w[1 true].include?(settings['oauth_enabled'].to_s.downcase)

      # Don't show OAuth button if SSO-only mode is enabled (user should be redirected before seeing this)
      return '' if %w[1 true].include?(settings['oauth_sso_only'].to_s.downcase)

      provider_name = settings['oauth_provider_name'] || 'OAuth Provider'
      login_text = l(:label_login_with_provider, scope: :bless_this_redmine_sso, provider: h(provider_name))
      logout_url = settings['oauth_logout_url'].to_s
      logout_label = l(:label_sso_logout, scope: :bless_this_redmine_sso)

      button_html = <<~HTML
        <div id="oauth-login">
          <form action="/oauth/authorize" method="get">
            <input type="submit" value="#{login_text}" id="oauth-login-submit" />
          </form>
        </div>
      HTML

      script_html = ''
      unless logout_url.blank?
        script_html = <<~HTML
          <script>
            document.addEventListener('DOMContentLoaded', function() {
              var menu = document.querySelector('#top-menu #account ul');
              if (menu) {
                var li = document.createElement('li');
                var link = document.createElement('a');
                link.href = '#{h(logout_url)}';
                link.textContent = #{logout_label.to_json};
                link.className = 'logout';
                li.appendChild(link);
                menu.appendChild(li);
              }
            });
          </script>
        HTML
      end

      (button_html + script_html).html_safe
    end

    def view_layouts_base_html_head(_context = {})
      stylesheet_link_tag('bless_this_redmine_sso', plugin: 'bless_this_redmine_sso')
    end
  end
end
