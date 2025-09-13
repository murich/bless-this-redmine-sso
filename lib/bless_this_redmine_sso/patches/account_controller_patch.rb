module BlessThisRedmineSso
  module Patches
    module AccountControllerPatch
      def self.included(base)
        base.class_eval do
          prepend InstanceMethods
        end
      end

      module InstanceMethods
        def login
          # Check if SSO-only mode is enabled
          settings = Setting.plugin_bless_this_redmine_sso
          if %w[1 true].include?(settings['oauth_enabled'].to_s.downcase) &&
             %w[1 true].include?(settings['oauth_sso_only'].to_s.downcase)
            # Redirect to OAuth authorization unless this is a callback
            unless request.path.include?('/oauth/')
              Rails.logger.info "SSO-only mode enabled, redirecting to OAuth provider"
              url = '/oauth/authorize'
              if session.delete(:oauth_prompt_login)
                separator = url.include?('?') ? '&' : '?'
                url = "#{url}#{separator}prompt=login"
              end
              redirect_to url
              return
            end
          end
          
          # Call original login method
          super
        end

        def logout
          settings = Setting.plugin_bless_this_redmine_sso
          logout_url = settings['oauth_logout_url'].to_s
          oauth_enabled = %w[1 true].include?(settings['oauth_enabled'].to_s.downcase)

          if oauth_enabled && logout_url.present? && session[:oauth_logged_in]
            # End the Redmine session without triggering the default redirect
            logout_user
            session.delete(:oauth_logged_in)
            redirect_to logout_url
          else
            # Force provider to show the login screen on next authorization when SSO is enabled
            session[:oauth_prompt_login] = true if oauth_enabled
            super
          end
        end
      end
    end
  end
end

# Apply the patch
unless AccountController.included_modules.include?(BlessThisRedmineSso::Patches::AccountControllerPatch)
  AccountController.send(:include, BlessThisRedmineSso::Patches::AccountControllerPatch)
end
