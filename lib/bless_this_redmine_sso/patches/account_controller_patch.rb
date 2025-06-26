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
          if settings['oauth_enabled'] && settings['oauth_sso_only']
            # Redirect to OAuth authorization unless this is a callback or logout
            unless params[:action] == 'logout' || request.path.include?('/oauth/')
              Rails.logger.info "SSO-only mode enabled, redirecting to OAuth provider"
              redirect_to '/oauth/authorize'
              return
            end
          end
          
          # Call original login method
          super
        end
      end
    end
  end
end

# Apply the patch
unless AccountController.included_modules.include?(BlessThisRedmineSso::Patches::AccountControllerPatch)
  AccountController.send(:include, BlessThisRedmineSso::Patches::AccountControllerPatch)
end