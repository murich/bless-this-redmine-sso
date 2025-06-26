class OauthController < ApplicationController
  skip_before_action :verify_authenticity_token
  
  def authorize
    # Redirect to OAuth authorization endpoint
    settings = Setting.plugin_bless_this_redmine_sso
    
    unless oauth_configured?
      flash[:error] = "OAuth SSO is not properly configured"
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
    
    auth_url = "#{authorize_url}?" \
               "client_id=#{CGI.escape(client_id)}&" \
               "redirect_uri=#{CGI.escape(redirect_uri)}&" \
               "scope=#{CGI.escape(scope)}&" \
               "response_type=code&" \
               "state=#{CGI.escape(state)}"
    
    redirect_to auth_url
  end
  
  def callback
    # Handle callback from OAuth provider
    code = params[:code]
    state = params[:state]
    
    # Verify state parameter
    unless state.present? && state == session[:oauth_state]
      flash[:error] = "Invalid OAuth state parameter"
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
            
            if user&.active?
              # Log the user in
              user.last_login_on = Time.now
              user.save!
              self.logged_user = user
              Rails.logger.info "Successful OAuth authentication for '#{user.login}' from #{request.remote_ip}"
              redirect_to my_page_path
            else
              flash[:error] = "User account is not active"
              redirect_to signin_path
            end
          else
            flash[:error] = "Failed to get user information from OAuth provider"
            redirect_to signin_path
          end
        else
          flash[:error] = "Failed to exchange authorization code"
          redirect_to signin_path
        end
      rescue => e
        Rails.logger.error "OAuth callback error: #{e.message}"
        Rails.logger.error e.backtrace.join("\n")
        flash[:error] = "Authentication failed"
        redirect_to signin_path
      end
    else
      error_msg = params[:error] || "Unknown error"
      flash[:error] = "OAuth failed: #{error_msg}"
      redirect_to signin_path
    end
  end

  private

  def oauth_configured?
    settings = Setting.plugin_bless_this_redmine_sso
    return false unless settings['oauth_enabled']
    
    required_settings = ['oauth_client_id', 'oauth_client_secret', 'oauth_authorize_url', 'oauth_token_url', 'oauth_userinfo_url']
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

    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = (uri.scheme == 'https')
    
    request = Net::HTTP::Post.new(uri)
    request.set_form_data(params)
    request['Accept'] = 'application/json'

    response = http.request(request)
    
    if response.code == '200'
      JSON.parse(response.body)
    else
      Rails.logger.error "Token exchange failed: #{response.body}"
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
    
    request = Net::HTTP::Get.new(uri)
    request['Authorization'] = "Bearer #{access_token}"
    request['Accept'] = 'application/json'

    response = http.request(request)
    
    if response.code == '200'
      JSON.parse(response.body)
    else
      Rails.logger.error "Get user info failed: #{response.body}"
      nil
    end
  end

  def find_or_create_user(user_info)
    # Extract user data from OAuth response
    username = user_info['name'] || user_info['preferred_username'] || user_info['sub'] || user_info['login']
    email = user_info['email']
    first_name = user_info['given_name'] || user_info['firstName'] || user_info['first_name'] || ''
    last_name = user_info['family_name'] || user_info['lastName'] || user_info['last_name'] || ''

    # Find existing user by login or email
    user = User.find_by(login: username) || User.find_by(mail: email)

    unless user
      # Create new user
      user = User.new(
        login: username,
        mail: email,
        firstname: first_name,
        lastname: last_name,
        status: User::STATUS_ACTIVE,
        language: Setting.default_language,
        mail_notification: Setting.default_notification_option
      )
      
      # Set a random password (user will use OAuth)
      user.password = SecureRandom.hex(20)
      user.password_confirmation = user.password
      
      if user.save
        Rails.logger.info "Created new user via OAuth: #{username}"
      else
        Rails.logger.error "Failed to create user: #{user.errors.full_messages.join(', ')}"
        return nil
      end
    else
      # Update user info from OAuth if needed
      updated = false
      if user.firstname != first_name && first_name.present?
        user.firstname = first_name
        updated = true
      end
      if user.lastname != last_name && last_name.present?
        user.lastname = last_name
        updated = true
      end
      if user.mail != email && email.present?
        user.mail = email
        updated = true
      end
      
      user.save if updated
    end

    user
  end
end