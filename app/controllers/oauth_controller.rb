require 'json'
require 'securerandom'
require 'uri'
require 'base64'
require 'digest'

class OauthController < ApplicationController
  # Allow OAuth endpoints to be accessed without prior Redmine login
  skip_before_action :check_if_login_required, only: %i[authorize callback], raise: false
  
  def authorize
    # Redirect to OAuth authorization endpoint
    settings = Setting.plugin_bless_this_redmine_sso
    
    unless oauth_configured?
      flash[:error] = l(:flash_oauth_not_configured, scope: :bless_this_redmine_sso)
      redirect_to signin_path
      return
    end
    
    client_id = settings['oauth_client_id']
    redirect_uri = settings['oauth_redirect_uri'].presence || "#{request.base_url}/oauth/callback"
    scope = settings['oauth_scope']
    authorize_url = settings['oauth_authorize_url']
    
    # Generate state parameter for security
    state = SecureRandom.hex(16)
    session[:oauth_state] = state

    pkce_enabled = %w[1 true].include?(settings['oauth_pkce'].to_s.downcase)
    if pkce_enabled
      code_verifier = SecureRandom.urlsafe_base64(32)
      session[:oauth_code_verifier] = code_verifier
      code_challenge = Base64.urlsafe_encode64(Digest::SHA256.digest(code_verifier)).delete('=')
    end

    params = {
      client_id: client_id,
      redirect_uri: redirect_uri,
      scope: scope,
      response_type: 'code',
      state: state
    }

    if pkce_enabled
      params[:code_challenge] = code_challenge
      params[:code_challenge_method] = 'S256'
    end

    auth_url = "#{authorize_url}?#{URI.encode_www_form(params)}"

    redirect_to auth_url
  end
  
  def callback
    # Handle callback from OAuth provider
    settings = Setting.plugin_bless_this_redmine_sso
    code = params[:code]
    state = params[:state]
    
    # Verify state parameter
    unless state.present? && state == session[:oauth_state]
      flash[:error] = l(:flash_invalid_state, scope: :bless_this_redmine_sso)
      redirect_to signin_path
      return
    end
    
    session.delete(:oauth_state)
    
    if code.present?
      begin
        # Exchange code for access token
        token_response = exchange_code_for_token(code)
        
        if token_response && token_response['access_token']
          # Get user info from OAuth provider
          user_info = get_user_info(token_response['access_token'])
          Rails.logger.info "OAuth user info: #{user_info.inspect}"
          
          if user_info
            # Find or create user in Redmine
            user = find_or_create_user(user_info)
            if user == :user_not_found
              flash[:error] = l(:flash_authentication_failed, scope: :bless_this_redmine_sso)
              redirect_to signin_path
            elsif user&.errors&.any?
              flash[:error] = user.errors.full_messages.join(', ')
              redirect_to signin_path
            elsif user&.active?
              # Log the user in
              user.last_login_on = Time.now
              user.save!
              self.logged_user = user
              session[:oauth_logged_in] = true
              session.delete(:must_activate_twofa) if %w[1 true].include?(settings['oauth_bypass_twofa'].to_s.downcase)
              Rails.logger.info "Successful OAuth authentication for '#{user.login}' from #{request.remote_ip}"
              redirect_to my_page_path
            else
              flash[:error] = l(:flash_user_inactive, scope: :bless_this_redmine_sso)
              redirect_to signin_path
            end
          else
            flash[:error] = l(:flash_user_info_failed, scope: :bless_this_redmine_sso)
            redirect_to signin_path
          end
        else
          flash[:error] = l(:flash_exchange_code_failed, scope: :bless_this_redmine_sso)
          redirect_to signin_path
        end
      rescue => e
        Rails.logger.error "OAuth callback error: #{e.message}"
        Rails.logger.error e.backtrace.join("\n")
        flash[:error] = l(:flash_authentication_failed, scope: :bless_this_redmine_sso)
        redirect_to signin_path
      end
    else
      error_msg = params[:error] || l(:flash_unknown_error, scope: :bless_this_redmine_sso)
      flash[:error] = l(:flash_oauth_failed, scope: :bless_this_redmine_sso, error: error_msg)
      redirect_to signin_path
    end
  end

  private

  def oauth_configured?
    settings = Setting.plugin_bless_this_redmine_sso
    return false unless %w[1 true].include?(settings['oauth_enabled'].to_s.downcase)

    required_settings = [
      'oauth_client_id',
      'oauth_client_secret',
      'oauth_authorize_url',
      'oauth_token_url',
      'oauth_userinfo_url'
    ]
    required_settings.all? { |setting| settings[setting].present? }
  end

  def exchange_code_for_token(code)
    require 'net/http'
    require 'uri'
    require 'json'

    settings = Setting.plugin_bless_this_redmine_sso
    uri = URI(settings['oauth_token_url'])
    
    redirect_uri = settings['oauth_redirect_uri'].presence || "#{request.base_url}/oauth/callback"
    
    params = {
      'grant_type' => 'authorization_code',
      'client_id' => settings['oauth_client_id'],
      'client_secret' => settings['oauth_client_secret'],
      'code' => code,
      'redirect_uri' => redirect_uri
    }

    pkce_enabled = %w[1 true].include?(settings['oauth_pkce'].to_s.downcase)
    code_verifier = session.delete(:oauth_code_verifier)
    params['code_verifier'] = code_verifier if pkce_enabled && code_verifier

    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = (uri.scheme == 'https')
    http.open_timeout = 5
    http.read_timeout = 5

    request = Net::HTTP::Post.new(uri)
    request.set_form_data(params)
    request['Accept'] = 'application/json'
    begin
      response = http.request(request)

      if response.code == '200'
        JSON.parse(response.body)
      else
        Rails.logger.error "Token exchange failed: #{response.body}"
        nil
      end
    rescue Net::OpenTimeout, Net::ReadTimeout => e
      Rails.logger.error "Token exchange timeout: #{e.message}"
      nil
    rescue StandardError => e
      Rails.logger.error "Token exchange error: #{e.message}"
      nil
    end
  end

  def get_user_info(access_token)
    require 'net/http'
    require 'uri'
    require 'json'

    settings = Setting.plugin_bless_this_redmine_sso
    uri = URI(settings['oauth_userinfo_url'])
    
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = (uri.scheme == 'https')
    http.open_timeout = 5
    http.read_timeout = 5

    request = Net::HTTP::Get.new(uri)
    request['Authorization'] = "Bearer #{access_token}"
    request['Accept'] = 'application/json'
    begin
      response = http.request(request)

      if response.code == '200'
        JSON.parse(response.body)
      else
        Rails.logger.error "Get user info failed: #{response.body}"
        nil
      end
    rescue Net::OpenTimeout, Net::ReadTimeout => e
      Rails.logger.error "Get user info timeout: #{e.message}"
      nil
    rescue StandardError => e
      Rails.logger.error "Get user info error: #{e.message}"
      nil
    end
  end

  def find_or_create_user(user_info)
    # Extract user data from OAuth response using configurable mappings
    settings = Setting.plugin_bless_this_redmine_sso

    login_keys = settings['oauth_login_field'].to_s.split(',').map(&:strip)
    email_keys = settings['oauth_email_field'].to_s.split(',').map(&:strip)
    firstname_keys = settings['oauth_firstname_field'].to_s.split(',').map(&:strip)
    lastname_keys = settings['oauth_lastname_field'].to_s.split(',').map(&:strip)

    resolved_custom_fields = {}
    if defined?(UserCustomField)
      UserCustomField.all.each do |cf|
        key_setting = settings["oauth_custom_field_#{cf.id}"]
        next if key_setting.blank?
        key_list = key_setting.to_s.split(',').map(&:strip)
        value = key_list.map { |key| user_info[key] }.find(&:present?)
        next if value.blank?
        resolved_custom_fields[cf.id.to_s] = value
      end
    end

    username = login_keys.map { |key| user_info[key] }.find(&:present?) ||
               user_info['name'] || user_info['preferred_username'] || user_info['sub'] || user_info['login']
    email = email_keys.map { |key| user_info[key] }.find(&:present?) ||
            user_info['email']
    email = email.to_s.downcase if email.present?
    first_name = firstname_keys.map { |key| user_info[key] }.find(&:present?) ||
                 user_info['given_name'] || user_info['firstName'] || user_info['first_name'] || ''
    last_name = lastname_keys.map { |key| user_info[key] }.find(&:present?) ||
                user_info['family_name'] || user_info['lastName'] || user_info['last_name'] || ''

    # Find existing user by login. Optionally allow email-based association
    # when explicitly enabled in settings.
    match_by_email = %w[1 true].include?(settings['oauth_match_by_email'].to_s.downcase)

    user = User.find_by(login: username) if username.present?
    if user.nil? && match_by_email && email.present?
      user = User.find_by_mail(email)
    end

    unless user
      auto_create = %w[1 true].include?(settings['oauth_auto_create'].to_s.downcase)
      return :user_not_found unless auto_create

      user = User.new(
        login: username,
        firstname: first_name,
        lastname: last_name,
        status: User::STATUS_ACTIVE,
        language: Setting.default_language,
        mail_notification: Setting.default_notification_option
      )
      user.build_email_address(address: email) if email.present?

      # Set a random password (user will use OAuth). Prefer Redmine's own
      # generator when available so it respects configured password policies,
      # otherwise fall back to our local implementation.
      if user.respond_to?(:random_password)
        user.random_password
      else
        password = generate_random_password
        user.password = password
        user.password_confirmation = password
      end

      user.custom_field_values = resolved_custom_fields if resolved_custom_fields.any?

      if user.save
        Rails.logger.info "Created new user via OAuth: #{username}"

        settings['oauth_default_groups'].to_s.split(',').map(&:strip).reject(&:blank?).each do |gid|
          begin
            group = Group.find(gid)
            user.groups << group unless user.groups.include?(group)
          rescue ActiveRecord::RecordNotFound
            Rails.logger.warn "Default group not found: #{gid}"
          end
        end
        unless user.save
          Rails.logger.error "Failed to update user groups: #{user.errors.full_messages.join(', ')}"
          return user
        end
      else
        Rails.logger.error "Failed to create user: #{user.errors.full_messages.join(', ')}"
        return user
      end
    else
      # Update user info from OAuth if needed
      update_existing = %w[1 true].include?(settings['oauth_update_existing'].to_s.downcase)
      updated = false
      if update_existing
        if user.firstname != first_name && first_name.present?
          user.firstname = first_name
          updated = true
        end
        if user.lastname != last_name && last_name.present?
          user.lastname = last_name
          updated = true
        end
        if email.present? && !user.mail.casecmp?(email)
          if user.email_address
            user.email_address.update(address: email)
          else
            user.build_email_address(address: email)
          end
          updated = true
        end

        resolved_custom_fields.each do |cf_id, value|
          if user.custom_field_values[cf_id].to_s != value.to_s
            user.custom_field_values[cf_id] = value
            updated = true
          end
        end
      end

      if updated && !user.save
        Rails.logger.error "Failed to update user: #{user.errors.full_messages.join(', ')}"
        return user
      end
    end

    user
  end

  # Fallback random password generator mimicking Redmine 6's implementation.
  # Users authenticated via OAuth won't need this password, but it must pass
  # Redmine's validation rules.
  def generate_random_password(length = 40)
    chars_list = [('A'..'Z').to_a, ('a'..'z').to_a, ('0'..'9').to_a]

    special_required = !defined?(Setting) ||
      (Setting.respond_to?(:password_required_char_classes) &&
       Setting.password_required_char_classes.include?('special_chars'))

    if special_required
      specials = if defined?(Setting) && Setting.const_defined?(:PASSWORD_CHAR_CLASSES)
                   ("\x20".."\x7e").to_a.select do |c|
                     c =~ Setting::PASSWORD_CHAR_CLASSES['special_chars']
                   end
                 else
                   %w[! @ # $ % ^ & *]
                 end
      chars_list << specials
    end

    chars_list.each {|v| v.reject! {|c| %(0O1l|'"`*).include?(c)}}

    password = +''
    chars_list.each do |chars|
      password << chars[SecureRandom.random_number(chars.size)]
      length -= 1
    end
    chars = chars_list.flatten
    length.times {password << chars[SecureRandom.random_number(chars.size)]}
    password.chars.shuffle(random: SecureRandom).join
  end
end
