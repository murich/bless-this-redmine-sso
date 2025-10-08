module BlessThisRedmineSso
  module Patches
    module MyControllerPatch
      def password
        Rails.logger.info "=== MyControllerPatch#password called ==="

        settings = Setting.plugin_bless_this_redmine_sso
        Rails.logger.info "Settings: #{settings.inspect}"

        sso_only = settings['oauth_sso_only']
        Rails.logger.info "SSO Only value: #{sso_only.inspect} (class: #{sso_only.class})"
        Rails.logger.info "SSO Only == '1': #{sso_only == '1'}"
        Rails.logger.info "SSO Only == true: #{sso_only == true}"

        # If SSO-only mode is enabled, ALL users must use external password management
        if settings['oauth_sso_only'] == '1' || settings['oauth_sso_only'] == true
          provider_name = settings['oauth_provider_name'] || 'SSO Provider'
          casdoor_url = ENV['CASDOOR_EXTERNAL_URL'] || 'http://localhost:8082'

          Rails.logger.info "SSO-only mode active, redirecting to #{casdoor_url}/account"

          flash[:error] = "Password management is handled by #{provider_name}. Please visit your SSO provider to change your password."
          redirect_to "#{casdoor_url}/account" and return
        end

        # If SSO-only is disabled, check if current user is an OAuth user
        if User.current.respond_to?(:is_oauth_user?) && User.current.is_oauth_user?
          provider_name = settings['oauth_provider_name'] || 'SSO Provider'
          casdoor_url = ENV['CASDOOR_EXTERNAL_URL'] || 'http://localhost:8082'

          Rails.logger.info "OAuth user detected, redirecting to #{casdoor_url}/account"

          flash[:error] = "Password management for #{provider_name} users is handled externally. Please visit #{provider_name} to change your password."
          redirect_to "#{casdoor_url}/account" and return
        end

        Rails.logger.info "No redirect conditions met, calling super"
        # Call original password method for non-OAuth users
        super
      end
    end
  end
end

