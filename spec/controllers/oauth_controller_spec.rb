# frozen_string_literal: true

require_relative '../rails_helper'
require_relative '../../lib/bless_this_redmine_sso/discovery'
require 'securerandom'
require 'jwt'
require 'openssl'
require 'base64'
require 'digest'
require 'json'

if defined?(OauthController) && defined?(Setting)
  RSpec.describe OauthController, type: :controller do
    describe 'GET #authorize' do
      context 'when OAuth is disabled' do
        before do
          Setting.plugin_bless_this_redmine_sso = { 'oauth_enabled' => '0' }
        end

        it 'redirects to signin when OAuth is not configured' do
          get :authorize
          expect(response).to redirect_to(signin_path)
        end
      end

      context 'when OAuth is enabled' do
        before do
          Setting.plugin_bless_this_redmine_sso = {
            'oauth_enabled' => '1',
            'oauth_authorize_url' => 'https://example.com/authorize',
            'oauth_client_id' => 'cid',
            'oauth_redirect_uri' => 'http://test.host/oauth/callback',
            'oauth_scope' => 'openid',
            'oauth_client_secret' => 'secret',
            'oauth_token_url' => 'https://example.com/token',
            'oauth_userinfo_url' => 'https://example.com/userinfo',
            'oauth_pkce' => '0'
          }
        end

        it 'redirects to the provider without PKCE params' do
          get :authorize
          expect(response.location).to include('example.com/authorize')
          expect(response.location).not_to include('code_challenge')
          expect(session[:oauth_code_verifier]).to be_nil
        end
      end

      context 'when PKCE is enabled' do
        before do
          Setting.plugin_bless_this_redmine_sso = {
            'oauth_enabled' => '1',
            'oauth_authorize_url' => 'https://example.com/authorize',
            'oauth_client_id' => 'cid',
            'oauth_redirect_uri' => 'http://test.host/oauth/callback',
            'oauth_scope' => 'openid',
            'oauth_client_secret' => 'secret',
            'oauth_token_url' => 'https://example.com/token',
            'oauth_userinfo_url' => 'https://example.com/userinfo',
            'oauth_pkce' => '1'
          }
        end

        it 'stores verifier and includes PKCE params' do
          get :authorize
          expect(response.location).to include('code_challenge=')
          expect(response.location).to include('code_challenge_method=S256')
          expect(session[:oauth_code_verifier]).to be_present
        end
      end

      context 'when OAuth is misconfigured' do
        before do
          Setting.plugin_bless_this_redmine_sso = {
            'oauth_enabled' => '1',
            'oauth_authorize_url' => 'https://example.com/authorize',
            'oauth_client_id' => 'cid',
            'oauth_redirect_uri' => 'http://test.host/oauth/callback',
            'oauth_scope' => 'openid',
            'oauth_client_secret' => 'secret',
            'oauth_token_url' => 'https://example.com/token'
            # intentionally missing oauth_userinfo_url
          }
        end

        it 'redirects to signin when required settings are missing' do
          get :authorize
          expect(response).to redirect_to(signin_path)
          expect(flash[:error]).to be_present
        end
      end
    end

    describe 'GET #callback' do
      before do
        Setting.plugin_bless_this_redmine_sso = { 'oauth_enabled' => '1' }
      end

      it 'redirects to signin when state does not match' do
        session[:oauth_state] = 'expected'
        get :callback, params: { state: 'mismatch' }
        expect(response).to redirect_to(signin_path)
      end

      it 'shows validation errors when user creation fails' do
        session[:oauth_state] = 'expected'
        allow(controller).to receive(:exchange_code_for_token).and_return('access_token' => 'token', 'id_token' => 'jwt')
        allow(controller).to receive(:verify_id_token).and_return('sub' => 'user-1')
        allow(controller).to receive(:get_user_info).and_return({})

        errors = double('errors', any?: true, full_messages: ["Login can't be blank"])
        user = double('User', errors: errors, active?: true)
        allow(controller).to receive(:find_or_create_user).and_return(user)

        get :callback, params: { state: 'expected', code: 'abc' }

        expect(flash[:error]).to include("Login can't be blank")
        expect(response).to redirect_to(signin_path)
      end

      it 'shows an error when id_token validation fails' do
        session[:oauth_state] = 'expected'
        allow(controller).to receive(:exchange_code_for_token).and_return('access_token' => 'token', 'id_token' => 'invalid')
        expect(controller).to receive(:verify_id_token).and_raise(OauthController::IdTokenValidationError.new('not valid'))
        expect(controller).not_to receive(:get_user_info)

        get :callback, params: { state: 'expected', code: 'abc' }

        expect(flash[:error]).to include('not valid')
        expect(response).to redirect_to(signin_path)
      end
    end

    describe 'POST #discover' do
      before do
        allow(controller).to receive(:require_admin)
      end

      it 'returns discovery data when successful' do
        allow(BlessThisRedmineSso::Discovery).to receive(:discover).and_return(
          settings: { 'oauth_authorize_url' => 'https://example.com/auth' },
          warnings: ['check something'],
          discovery_url: 'https://example.com/.well-known/openid-configuration'
        )

        post :discover, params: { provider: 'google' }

        expect(response).to be_successful
        body = JSON.parse(response.body)
        expect(body['success']).to eq(true)
        expect(body['settings']['oauth_authorize_url']).to eq('https://example.com/auth')
        expect(body['warnings']).to include('check something')
      end

      it 'returns errors from the discovery service' do
        allow(BlessThisRedmineSso::Discovery).to receive(:discover).and_raise(
          BlessThisRedmineSso::Discovery::Error, 'boom'
        )

        post :discover, params: { provider: 'custom' }

        expect(response.status).to eq(422)
        body = JSON.parse(response.body)
        expect(body['success']).to eq(false)
        expect(body['error']).to include('boom')
      end
    end

    describe '#exchange_code_for_token timeouts' do
      it 'returns nil and logs error on open timeout' do
        Setting.plugin_bless_this_redmine_sso = {
          'oauth_client_id' => 'cid',
          'oauth_client_secret' => 'secret',
          'oauth_token_url' => 'https://example.com/token',
          'oauth_redirect_uri' => 'http://test.host/oauth/callback'
        }

        http = instance_double(Net::HTTP)
        allow(Net::HTTP).to receive(:new).and_return(http)
        allow(http).to receive(:use_ssl=)
        allow(http).to receive(:open_timeout=)
        allow(http).to receive(:read_timeout=)

        request = instance_double(Net::HTTP::Post, set_form_data: nil)
        allow(Net::HTTP::Post).to receive(:new).and_return(request)
        allow(request).to receive(:[]=)

        allow(http).to receive(:request).and_raise(Net::OpenTimeout)

        logger = double('logger', error: nil)
        allow(Rails).to receive(:logger).and_return(logger)
        expect(logger).to receive(:error).with(/Token exchange timeout/)

        result = controller.send(:exchange_code_for_token, 'code')
        expect(result).to be_nil
      end

      it 'returns nil and logs error on read timeout' do
        Setting.plugin_bless_this_redmine_sso = {
          'oauth_client_id' => 'cid',
          'oauth_client_secret' => 'secret',
          'oauth_token_url' => 'https://example.com/token',
          'oauth_redirect_uri' => 'http://test.host/oauth/callback'
        }

        http = instance_double(Net::HTTP)
        allow(Net::HTTP).to receive(:new).and_return(http)
        allow(http).to receive(:use_ssl=)
        allow(http).to receive(:open_timeout=)
        allow(http).to receive(:read_timeout=)

        request = instance_double(Net::HTTP::Post, set_form_data: nil)
        allow(Net::HTTP::Post).to receive(:new).and_return(request)
        allow(request).to receive(:[]=)

        allow(http).to receive(:request).and_raise(Net::ReadTimeout)

        logger = double('logger', error: nil)
        allow(Rails).to receive(:logger).and_return(logger)
        expect(logger).to receive(:error).with(/Token exchange timeout/)

        result = controller.send(:exchange_code_for_token, 'code')
        expect(result).to be_nil
      end
    end

    describe '#exchange_code_for_token' do
      before do
        @form_params = {}
        @http = double('http')
        allow(Net::HTTP).to receive(:new).and_return(@http)
        allow(@http).to receive(:use_ssl=)
        allow(@http).to receive(:open_timeout=)
        allow(@http).to receive(:read_timeout=)
        allow(@http).to receive(:request).and_return(double(code: '200', body: '{}'))
        request = double('request')
        allow(Net::HTTP::Post).to receive(:new).and_return(request)
        allow(request).to receive(:[]=)
        allow(request).to receive(:set_form_data) { |p| @form_params = p }
      end

      it 'omits code_verifier when PKCE disabled' do
        Setting.plugin_bless_this_redmine_sso = {
          'oauth_token_url' => 'https://example.com/token',
          'oauth_client_id' => 'cid',
          'oauth_client_secret' => 'secret',
          'oauth_redirect_uri' => 'http://test.host/oauth/callback',
          'oauth_pkce' => '0'
        }
        controller.send(:exchange_code_for_token, 'abc')
        expect(@form_params).not_to include('code_verifier')
      end

      it 'sends code_verifier when PKCE enabled' do
        Setting.plugin_bless_this_redmine_sso = {
          'oauth_token_url' => 'https://example.com/token',
          'oauth_client_id' => 'cid',
          'oauth_client_secret' => 'secret',
          'oauth_redirect_uri' => 'http://test.host/oauth/callback',
          'oauth_pkce' => '1'
        }
        session[:oauth_code_verifier] = 'verifier'
        controller.send(:exchange_code_for_token, 'abc')
        expect(@form_params).to include('code_verifier' => 'verifier')
      end

      it 'stores the id_token in the session when provided' do
        Setting.plugin_bless_this_redmine_sso = {
          'oauth_token_url' => 'https://example.com/token',
          'oauth_client_id' => 'cid',
          'oauth_client_secret' => 'secret',
          'oauth_redirect_uri' => 'http://test.host/oauth/callback'
        }
        allow(@http).to receive(:request).and_return(double(code: '200', body: '{"id_token":"jwt-token"}'))

        result = controller.send(:exchange_code_for_token, 'abc')

        expect(result['id_token']).to eq('jwt-token')
        expect(session[:oauth_id_token]).to eq('jwt-token')
      end

      it 'logs an error and returns nil when the response is unsuccessful' do
        Setting.plugin_bless_this_redmine_sso = {
          'oauth_token_url' => 'https://example.com/token',
          'oauth_client_id' => 'cid',
          'oauth_client_secret' => 'secret',
          'oauth_redirect_uri' => 'http://test.host/oauth/callback'
        }
        allow(@http).to receive(:request).and_return(double(code: '500', body: 'boom'))
        session[:oauth_id_token] = 'stale-token'

        logger = double('logger', error: nil)
        allow(Rails).to receive(:logger).and_return(logger)
        expect(logger).to receive(:error).with(/Token exchange failed: boom/)

        result = controller.send(:exchange_code_for_token, 'abc')

        expect(result).to be_nil
        expect(session[:oauth_id_token]).to be_nil
      end

      it 'logs an error and returns nil when parsing the response fails' do
        Setting.plugin_bless_this_redmine_sso = {
          'oauth_token_url' => 'https://example.com/token',
          'oauth_client_id' => 'cid',
          'oauth_client_secret' => 'secret',
          'oauth_redirect_uri' => 'http://test.host/oauth/callback'
        }
        allow(@http).to receive(:request).and_return(double(code: '200', body: '{'))

        logger = double('logger', error: nil)
        allow(Rails).to receive(:logger).and_return(logger)
        expect(logger).to receive(:error).with(/Token exchange error: /)

        result = controller.send(:exchange_code_for_token, 'abc')

        expect(result).to be_nil
        expect(session[:oauth_id_token]).to be_nil
      end
    end

    describe '#get_user_info' do
      let(:http) { instance_double(Net::HTTP) }
      let(:request) { instance_double(Net::HTTP::Get) }

      before do
        Setting.plugin_bless_this_redmine_sso = {
          'oauth_userinfo_url' => 'https://example.com/userinfo'
        }

        allow(Net::HTTP).to receive(:new).and_return(http)
        allow(Net::HTTP::Get).to receive(:new).and_return(request)
        allow(http).to receive(:use_ssl=)
        allow(http).to receive(:open_timeout=)
        allow(http).to receive(:read_timeout=)
      end

      it 'returns parsed user info on success' do
        headers = {}
        allow(request).to receive(:[]=) { |key, value| headers[key] = value }
        allow(http).to receive(:request).and_return(double(code: '200', body: '{"email":"user@example.com"}'))

        result = controller.send(:get_user_info, 'access-token')

        expect(result['email']).to eq('user@example.com')
        expect(headers['Authorization']).to eq('Bearer access-token')
        expect(headers['Accept']).to eq('application/json')
      end

      it 'logs an error and returns nil when the response is unsuccessful' do
        allow(request).to receive(:[]=)
        allow(http).to receive(:request).and_return(double(code: '401', body: 'unauthorized'))

        logger = double('logger', error: nil)
        allow(Rails).to receive(:logger).and_return(logger)
        expect(logger).to receive(:error).with(/Get user info failed: unauthorized/)

        result = controller.send(:get_user_info, 'access-token')

        expect(result).to be_nil
      end

      it 'logs an error and returns nil when parsing the response fails' do
        allow(request).to receive(:[]=)
        allow(http).to receive(:request).and_return(double(code: '200', body: '{'))

        logger = double('logger', error: nil)
        allow(Rails).to receive(:logger).and_return(logger)
        expect(logger).to receive(:error).with(/Get user info error: /)

        result = controller.send(:get_user_info, 'access-token')

        expect(result).to be_nil
      end

      it 'logs an error and returns nil when a timeout occurs' do
        allow(request).to receive(:[]=)
        allow(http).to receive(:request).and_raise(Net::ReadTimeout)

        logger = double('logger', error: nil)
        allow(Rails).to receive(:logger).and_return(logger)
        expect(logger).to receive(:error).with(/Get user info timeout/)

        result = controller.send(:get_user_info, 'access-token')

        expect(result).to be_nil
      end
    end

    describe 'OAuth integration flow' do
      let(:client_id) { 'cid-123' }
      let(:issuer) { 'https://issuer.example' }
      let(:secret) { 'super-secret' }
      let(:authorize_url) { 'https://example.com/authorize' }
      let(:token_url) { 'https://example.com/token' }
      let(:userinfo_url) { 'https://example.com/userinfo' }
      let(:logger) { double('logger', info: nil, error: nil) }

      before do
        Setting.plugin_bless_this_redmine_sso = {
          'oauth_enabled' => '1',
          'oauth_authorize_url' => authorize_url,
          'oauth_client_id' => client_id,
          'oauth_client_secret' => secret,
          'oauth_token_url' => token_url,
          'oauth_userinfo_url' => userinfo_url,
          'oauth_redirect_uri' => 'http://test.host/oauth/callback',
          'oauth_scope' => 'openid profile email',
          'oauth_pkce' => '1',
          'oauth_expected_issuer' => issuer,
          'oauth_expected_client_id' => client_id
        }

        allow(Rails).to receive(:logger).and_return(logger)
      end

      it 'completes the OAuth flow with PKCE and a valid id_token' do
        captured_form_params = {}
        headers = {}
        http_token = instance_double(Net::HTTP)
        http_userinfo = instance_double(Net::HTTP)
        allow(Net::HTTP).to receive(:new).and_return(http_token, http_userinfo)

        [http_token, http_userinfo].each do |http|
          allow(http).to receive(:use_ssl=)
          allow(http).to receive(:open_timeout=)
          allow(http).to receive(:read_timeout=)
        end

        post_request = instance_double(Net::HTTP::Post)
        allow(Net::HTTP::Post).to receive(:new).and_return(post_request)
        allow(post_request).to receive(:[]=)
        allow(post_request).to receive(:set_form_data) { |params| captured_form_params = params }

        id_token_payload = {
          'iss' => issuer,
          'aud' => client_id,
          'sub' => 'user-123',
          'exp' => (Time.now + 3600).to_i,
          'iat' => Time.now.to_i
        }
        id_token = JWT.encode(id_token_payload, secret, 'HS256')
        token_response = instance_double(
          Net::HTTPResponse,
          code: '200',
          body: JSON.generate('access_token' => 'access-token', 'id_token' => id_token)
        )
        allow(http_token).to receive(:request).and_return(token_response)

        get_request = instance_double(Net::HTTP::Get)
        allow(Net::HTTP::Get).to receive(:new).and_return(get_request)
        allow(get_request).to receive(:[]=) { |key, value| headers[key] = value }

        userinfo_body = JSON.generate('sub' => 'user-123', 'email' => 'user@example.com', 'name' => 'User Example')
        userinfo_response = instance_double(Net::HTTPResponse, code: '200', body: userinfo_body)
        allow(http_userinfo).to receive(:request).and_return(userinfo_response)

        errors = double('errors', any?: false, full_messages: [])
        user = double('User', errors: errors, active?: true, save!: true, login: 'user-123', id: 42)
        allow(user).to receive(:last_login_on=)
        captured_logged_user = nil
        allow(controller).to receive(:logged_user=) { |value| captured_logged_user = value }

        get :authorize
        authorize_location = response.location
        state = session[:oauth_state]
        code_verifier = session[:oauth_code_verifier]

        expect(state).to be_present
        expect(code_verifier).to be_present

        expected_challenge = Base64.urlsafe_encode64(Digest::SHA256.digest(code_verifier)).delete('=')
        expect(authorize_location).to include("code_challenge=#{expected_challenge}")
        expect(authorize_location).to include('code_challenge_method=S256')

        expect(controller).to receive(:verify_id_token).and_call_original
        expect(controller).to receive(:find_or_create_user)
          .with(hash_including('sub' => 'user-123', 'email' => 'user@example.com'))
          .and_return(user)

        get :callback, params: { state: state, code: 'auth-code' }

        expect(response).to redirect_to(my_page_path)
        expect(session[:oauth_logged_in]).to be true
        expect(session[:oauth_state]).to be_nil
        expect(session[:oauth_code_verifier]).to be_nil
        expect(session[:oauth_id_token]).to eq(id_token)
        expect(captured_logged_user).to eq(user)
        expect(captured_form_params['code_verifier']).to eq(code_verifier)
        expect(headers['Authorization']).to eq('Bearer access-token')
        expect(headers['Accept']).to eq('application/json')
      end

      it 'aborts the OAuth flow when id_token validation fails' do
        captured_form_params = {}
        http_token = instance_double(Net::HTTP)
        allow(Net::HTTP).to receive(:new).and_return(http_token)
        allow(http_token).to receive(:use_ssl=)
        allow(http_token).to receive(:open_timeout=)
        allow(http_token).to receive(:read_timeout=)

        post_request = instance_double(Net::HTTP::Post)
        allow(Net::HTTP::Post).to receive(:new).and_return(post_request)
        allow(post_request).to receive(:[]=)
        allow(post_request).to receive(:set_form_data) { |params| captured_form_params = params }

        invalid_token_payload = {
          'iss' => issuer,
          'aud' => client_id,
          'sub' => 'user-123',
          'exp' => (Time.now + 3600).to_i,
          'iat' => Time.now.to_i
        }
        invalid_token = JWT.encode(invalid_token_payload, 'other-secret', 'HS256')
        token_response = instance_double(
          Net::HTTPResponse,
          code: '200',
          body: JSON.generate('access_token' => 'access-token', 'id_token' => invalid_token)
        )
        allow(http_token).to receive(:request).and_return(token_response)

        allow(controller).to receive(:logged_user=)

        get :authorize
        state = session[:oauth_state]
        code_verifier = session[:oauth_code_verifier]

        expect(state).to be_present
        expect(code_verifier).to be_present

        expect(controller).to receive(:verify_id_token).and_call_original
        expect(controller).not_to receive(:find_or_create_user)
        expect(logger).to receive(:error).with(/ID token validation failed:/)

        get :callback, params: { state: state, code: 'auth-code' }

        expect(response).to redirect_to(signin_path)
        expect(session[:oauth_logged_in]).not_to be true
        expect(session[:oauth_id_token]).to be_nil
        expect(captured_form_params['code_verifier']).to eq(code_verifier)
      end
    end

    describe '#verify_id_token' do
      let(:secret) { 'secret-key' }
      let(:issuer) { 'https://issuer.example' }
      let(:client_id) { 'cid-123' }
      let(:base_payload) do
        {
          'iss' => issuer,
          'aud' => client_id,
          'sub' => 'user-1',
          'exp' => (Time.now + 3600).to_i,
          'iat' => Time.now.to_i
        }
      end

      let(:plugin_settings) do
        {
          'oauth_client_secret' => secret,
          'oauth_client_id' => client_id,
          'oauth_expected_issuer' => issuer,
          'oauth_expected_client_id' => client_id,
          'oauth_jwks_url' => ''
        }
      end

      before do
        Setting.plugin_bless_this_redmine_sso = plugin_settings
      end

      it 'returns claims for a valid token' do
        token = JWT.encode(base_payload, secret, 'HS256')
        claims = controller.send(:verify_id_token, token)
        expect(claims['sub']).to eq('user-1')
      end

      it 'raises an error when the signature is invalid' do
        token = JWT.encode(base_payload, 'other-secret', 'HS256')
        expect do
          controller.send(:verify_id_token, token)
        end.to raise_error(
          OauthController::IdTokenValidationError,
          I18n.t(:error_id_token_signature, scope: :bless_this_redmine_sso)
        )
      end

      it 'raises an error when the issuer does not match' do
        token = JWT.encode(base_payload.merge('iss' => 'https://other.example'), secret, 'HS256')
        expect do
          controller.send(:verify_id_token, token)
        end.to raise_error(
          OauthController::IdTokenValidationError,
          I18n.t(:error_id_token_invalid_issuer, scope: :bless_this_redmine_sso)
        )
      end

      it 'raises an error when the audience does not match' do
        token = JWT.encode(base_payload.merge('aud' => 'different-audience'), secret, 'HS256')
        expect do
          controller.send(:verify_id_token, token)
        end.to raise_error(
          OauthController::IdTokenValidationError,
          I18n.t(:error_id_token_invalid_audience, scope: :bless_this_redmine_sso)
        )
      end

      context 'with RS256 tokens' do
        let(:jwks_url) { 'https://example.com/jwks.json' }
        let(:plugin_settings) { super().merge('oauth_jwks_url' => jwks_url) }
        let(:rsa_key) { OpenSSL::PKey::RSA.generate(2048) }
        let(:jwk) { JWT::JWK::RSA.new(rsa_key) }

        before do
          allow(controller).to receive(:load_jwks_keys).with(jwks_url).and_return([jwk.export])
        end

        it 'returns claims for a valid token' do
          token = JWT.encode(base_payload, rsa_key, 'RS256', kid: jwk.kid)
          claims = controller.send(:verify_id_token, token)
          expect(claims['sub']).to eq('user-1')
        end

        it 'raises an error when the signature is invalid' do
          other_key = OpenSSL::PKey::RSA.generate(2048)
          token = JWT.encode(base_payload, other_key, 'RS256', kid: jwk.kid)

          expect do
            controller.send(:verify_id_token, token)
          end.to raise_error(
            OauthController::IdTokenValidationError,
            I18n.t(:error_id_token_signature, scope: :bless_this_redmine_sso)
          )
        end

        it 'raises an error when the key cannot be found' do
          allow(controller).to receive(:load_jwks_keys).with(jwks_url).and_return([])
          token = JWT.encode(base_payload, rsa_key, 'RS256', kid: jwk.kid)

          expect do
            controller.send(:verify_id_token, token)
          end.to raise_error(
            OauthController::IdTokenValidationError,
            I18n.t(:error_id_token_jwk_not_found, scope: :bless_this_redmine_sso, kid: jwk.kid)
          )
        end

        it 'raises an error when the kid header is missing' do
          token = JWT.encode(base_payload, rsa_key, 'RS256')

          expect do
            controller.send(:verify_id_token, token)
          end.to raise_error(
            OauthController::IdTokenValidationError,
            I18n.t(:error_id_token_missing_kid, scope: :bless_this_redmine_sso)
          )
        end
      end

      it 'raises an error when RS256 tokens are returned without a JWKS URL' do
        rsa_key = OpenSSL::PKey::RSA.generate(2048)
        token = JWT.encode(base_payload, rsa_key, 'RS256', kid: 'kid-123')

        expect do
          controller.send(:verify_id_token, token)
        end.to raise_error(
          OauthController::IdTokenValidationError,
          I18n.t(:error_id_token_missing_jwks_url, scope: :bless_this_redmine_sso)
        )
      end
    end

    describe '#find_or_create_user custom fields' do
      it 'maps oauth values to user custom fields' do
        unless defined?(User) && defined?(UserCustomField)
          skip 'User or UserCustomField not available'
        end

        cf = UserCustomField.create!(name: "Department #{SecureRandom.hex(4)}", field_format: 'string')
        Setting.plugin_bless_this_redmine_sso = {
          'oauth_login_field' => 'login',
          'oauth_email_field' => 'email',
          'oauth_firstname_field' => 'first_name',
          'oauth_lastname_field' => 'last_name',
          "oauth_custom_field_#{cf.id}" => 'dept',
          'oauth_auto_create' => '1'
        }

        login = "jdoe_cf_#{SecureRandom.hex(4)}"
        email = "#{login}@example.com"
        user_info = {
          'login' => login,
          'email' => email,
          'dept' => 'IT',
          'first_name' => 'John',
          'last_name' => 'Doe'
        }
        user = controller.send(:find_or_create_user, user_info)
        user.reload

        expect(user).to be_present
        expect(user.custom_field_value(cf)).to eq('IT')
      end
    end

    describe '#find_or_create_user login lookup' do
      it 'matches existing users regardless of login case by default' do
        unless defined?(User)
          skip 'User not available'
        end

        login = "case_login_#{SecureRandom.hex(4)}@example.com"
        user = User.new(
          login: login,
          firstname: 'Case',
          lastname: 'Tester',
          status: User::STATUS_ACTIVE
        )
        user.password = 'Passw0rd!'
        user.password_confirmation = 'Passw0rd!'
        user.mail = login
        user.save!

        Setting.plugin_bless_this_redmine_sso = {
          'oauth_login_field' => 'login',
          'oauth_firstname_field' => '',
          'oauth_lastname_field' => ''
        }

        user_info = { 'login' => login.upcase }
        result = controller.send(:find_or_create_user, user_info)

        expect(result.id).to eq(user.id)
      end

      it 'requires exact casing when case-insensitive matching is disabled' do
        unless defined?(User)
          skip 'User not available'
        end

        login = "case_sensitive_#{SecureRandom.hex(4)}@example.com"
        user = User.new(
          login: login,
          firstname: 'Case',
          lastname: 'Strict',
          status: User::STATUS_ACTIVE
        )
        user.password = 'Passw0rd!'
        user.password_confirmation = 'Passw0rd!'
        user.mail = login
        user.save!

        Setting.plugin_bless_this_redmine_sso = {
          'oauth_login_field' => 'login',
          'oauth_case_insensitive_login' => '0'
        }

        user_info = { 'login' => login.upcase }
        result = controller.send(:find_or_create_user, user_info)

        expect(result).to eq(:user_not_found)
      end

      it 'does not update login when case differs for existing user' do
        unless defined?(User)
          skip 'User not available'
        end

        login = "update_case_#{SecureRandom.hex(4)}@example.com"
        user = User.new(
          login: login,
          firstname: 'Old',
          lastname: 'Name',
          status: User::STATUS_ACTIVE
        )
        user.password = 'Passw0rd!'
        user.password_confirmation = 'Passw0rd!'
        user.mail = login
        user.save!

        Setting.plugin_bless_this_redmine_sso = {
          'oauth_login_field' => 'login',
          'oauth_firstname_field' => 'firstname',
          'oauth_update_existing' => '1',
          'oauth_case_insensitive_login' => '1'
        }

        user_info = { 'login' => login.upcase, 'firstname' => 'New' }
        result = controller.send(:find_or_create_user, user_info)

        expect(result.id).to eq(user.id)
        expect(result.reload.login).to eq(login)
        expect(result.firstname).to eq('New')
      end
    end

    describe '#find_or_create_user email lookup' do
      it 'does not associate by email when login differs' do
        unless defined?(User)
          skip 'User not available'
        end

        email = "match_#{SecureRandom.hex(4)}@example.com"
        existing_login = "existing_#{SecureRandom.hex(4)}"
        existing = User.new(login: existing_login, firstname: 'Ex', lastname: 'Ist', status: User::STATUS_ACTIVE)
        existing.password = 'Passw0rd!'
        existing.password_confirmation = 'Passw0rd!'
        existing.mail = email
        existing.save!

        Setting.plugin_bless_this_redmine_sso = {
          'oauth_login_field' => 'login',
          'oauth_email_field' => 'email',
          'oauth_firstname_field' => '',
          'oauth_lastname_field' => ''
        }

        user_info = { 'login' => "new_#{SecureRandom.hex(4)}", 'email' => email }
        user = controller.send(:find_or_create_user, user_info)

        expect(user).to eq(:user_not_found)
      end

      it 'associates by email when configured' do
        unless defined?(User)
          skip 'User not available'
        end

        email = "match_#{SecureRandom.hex(4)}@example.com"
        existing_login = "existing_#{SecureRandom.hex(4)}"
        existing = User.new(login: existing_login, firstname: 'Ex', lastname: 'Ist', status: User::STATUS_ACTIVE)
        existing.password = 'Passw0rd!'
        existing.password_confirmation = 'Passw0rd!'
        existing.mail = email
        existing.save!

        Setting.plugin_bless_this_redmine_sso = {
          'oauth_login_field' => 'login',
          'oauth_email_field' => 'email',
          'oauth_match_by_email' => '1'
        }

        user_info = { 'login' => "new_#{SecureRandom.hex(4)}", 'email' => email }
        user = controller.send(:find_or_create_user, user_info)

        expect(user).to eq(existing)
      end
    end

    describe '#find_or_create_user update failure' do
      it 'returns errors when updating an existing user fails' do
        unless defined?(User)
          skip 'User not available'
        end

        login = "jdoe_update_fail_#{SecureRandom.hex(4)}"
        user = User.new(login: login, firstname: 'John', lastname: 'Doe', status: User::STATUS_ACTIVE)
        user.password = 'Passw0rd!'
        user.password_confirmation = 'Passw0rd!'
        user.mail = "#{login}@example.com"
        user.save!

        Setting.plugin_bless_this_redmine_sso = {
          'oauth_login_field' => 'login',
          'oauth_firstname_field' => 'first_name',
          'oauth_lastname_field' => 'last_name',
          'oauth_update_existing' => '1'
        }

        errors = double('errors', any?: true, full_messages: ['save failed'])
        allow(User).to receive(:find_by).and_call_original
        allow(User).to receive(:find_by).with('LOWER(login) = ?', login.downcase).and_return(user)
        allow(user).to receive(:save).and_return(false)
        allow(user).to receive(:errors).and_return(errors)

        user_info = { 'login' => login, 'first_name' => 'Johnny', 'last_name' => 'Doe' }
        result = controller.send(:find_or_create_user, user_info)

        expect(result.errors.full_messages).to include('save failed')
      end
    end

    describe '#find_or_create_user email association' do
      it 'builds email address when creating a user' do
        unless defined?(User) && defined?(EmailAddress)
          skip 'User or EmailAddress not available'
        end

        Setting.plugin_bless_this_redmine_sso = {
          'oauth_login_field' => 'login',
          'oauth_email_field' => 'email',
          'oauth_auto_create' => '1'
        }

        user_info = { 'login' => 'jdoe_build', 'email' => 'jdoe_build@example.com' }
        user = controller.send(:find_or_create_user, user_info)

        expect(user).to be_present
        expect(user.email_address).to be_present
        expect(user.mail).to eq('jdoe_build@example.com')
      end

      it 'updates email address for existing user' do
        unless defined?(User) && defined?(EmailAddress)
          skip 'User or EmailAddress not available'
        end

        Setting.plugin_bless_this_redmine_sso = {
          'oauth_login_field' => 'login',
          'oauth_email_field' => 'email',
          'oauth_update_existing' => '1'
        }

        login = "jdoe_update_#{SecureRandom.hex(4)}"
        old_email = "old_#{SecureRandom.hex(4)}@example.com"
        new_email = "new_#{SecureRandom.hex(4)}@example.com"
        user = User.new(
          login: login,
          firstname: 'John',
          lastname: 'Doe',
          status: User::STATUS_ACTIVE,
          language: Setting.default_language,
          mail_notification: Setting.default_notification_option
        )
        user.build_email_address(address: old_email)
        user.password = 'Passw0rd!'
        user.password_confirmation = 'Passw0rd!'
        user.save!

        allow_any_instance_of(EmailAddress).to receive(:deliver_security_notification_update)
        user_info = { 'login' => login, 'email' => new_email }
        user = controller.send(:find_or_create_user, user_info)
        user.reload

        expect(user.email_address.address).to eq(new_email)
      end
    end

    describe '#find_or_create_user email association' do
      it 'preserves existing email when case only differs' do
        unless defined?(User) && defined?(EmailAddress)
          skip 'User or EmailAddress not available'
        end

        login = "jdoe_case_#{SecureRandom.hex(4)}"
        mixed_email = "MixedCase_#{SecureRandom.hex(4)}@example.com"
        user = User.create!(
          login: login,
          mail: mixed_email,
          firstname: 'John',
          lastname: 'Doe',
          password: 'Passw0rd!',
          password_confirmation: 'Passw0rd!'
        )

        Setting.plugin_bless_this_redmine_sso = {
          'oauth_login_field' => 'login',
          'oauth_email_field' => 'email',
          'oauth_firstname_field' => '',
          'oauth_lastname_field' => '',
          'oauth_update_existing' => '1'
        }

        user_info = { 'login' => login, 'email' => mixed_email.downcase }
        result = controller.send(:find_or_create_user, user_info)

        expect(result.id).to eq(user.id)
        expect(result.mail).to eq(mixed_email)
      end
    end
  end
else
  RSpec.describe 'OauthController', type: :controller do
    it 'is skipped because OauthController is not defined' do
      skip 'OauthController not available. Run specs within a Redmine environment.'
    end
  end
end
