module BlessThisRedmineSso
  class Hooks < Redmine::Hook::ViewListener
    # Add JavaScript to HEAD for OAuth users
    def view_layouts_base_html_head(context = {})
      user = User.current
      settings = Setting.plugin_bless_this_redmine_sso

      return '' unless settings['oauth_enabled']
      return '' unless user.logged? && user.respond_to?(:is_oauth_user?) && user.is_oauth_user?

      content = <<-HTML
        <script type="text/javascript">
          document.addEventListener('DOMContentLoaded', function() {
            // Only run on /my/account page
            if (window.location.pathname !== '/my/account') return;

            // Make firstname, lastname, and email fields read-only for OAuth users
            var firstnameField = document.getElementById('user_firstname');
            var lastnameField = document.getElementById('user_lastname');
            var emailField = document.getElementById('user_mail');

            if (firstnameField) {
              firstnameField.setAttribute('readonly', 'readonly');
              firstnameField.style.backgroundColor = '#f0f0f0';
              firstnameField.style.cursor = 'not-allowed';
            }

            if (lastnameField) {
              lastnameField.setAttribute('readonly', 'readonly');
              lastnameField.style.backgroundColor = '#f0f0f0';
              lastnameField.style.cursor = 'not-allowed';
            }

            if (emailField) {
              emailField.setAttribute('readonly', 'readonly');
              emailField.style.backgroundColor = '#f0f0f0';
              emailField.style.cursor = 'not-allowed';
            }

            // Add info message
            var infoSection = document.querySelector('.box.tabular');
            if (infoSection) {
              var infoDiv = document.createElement('div');
              infoDiv.style.cssText = 'background-color: #fffbcc; border: 1px solid #e7c157; padding: 10px; margin-bottom: 15px; border-radius: 4px;';
              infoDiv.innerHTML = '<strong>ℹ️ Note:</strong> Password management and User Information is handled by your corporate SSO provider. Please visit your SSO provider to change them.';
              infoSection.insertBefore(infoDiv, infoSection.firstChild);
            }
          });
        </script>
      HTML

      content.html_safe
    end
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

    # Make profile fields read-only for OAuth users on /my/account page
    def view_my_account(context = {})
      # This hook is not needed anymore - we use view_layouts_base_html_head instead
      # Keeping this as a placeholder for potential future use
      ''
    end
  end
end