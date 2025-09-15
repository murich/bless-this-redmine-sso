# frozen_string_literal: true

require_relative '../rails_helper'
require 'securerandom'
require 'jwt'
require 'openssl'
require_relative '../../lib/bless_this_redmine_sso/discovery'

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
      it 'returns nil and logs error on timeout' do
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
        allow(User).to receive(:find_by).with(login: login).and_return(user)
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
