# frozen_string_literal: true

require_relative '../../spec_helper'
require_relative '../../../lib/bless_this_redmine_sso/discovery'

RSpec.describe BlessThisRedmineSso::Discovery do
  let(:http) { instance_double(Net::HTTP) }
  let(:request) { instance_double(Net::HTTP::Get) }

  before do
    allow(Net::HTTP).to receive(:new).and_return(http)
    allow(http).to receive(:use_ssl=)
    allow(http).to receive(:open_timeout=)
    allow(http).to receive(:read_timeout=)
    allow(Net::HTTP::Get).to receive(:new).and_return(request)
    allow(request).to receive(:[]=)
  end

  def stub_response(body, code: '200')
    response = instance_double('HTTPResponse', code: code, body: body)
    allow(http).to receive(:request).and_return(response)
    response
  end

  describe '.discover' do
    it 'loads Google metadata via discovery and maps endpoints' do
      metadata = {
        'authorization_endpoint' => 'https://accounts.google.com/o/oauth2/v2/auth',
        'token_endpoint' => 'https://oauth2.googleapis.com/token',
        'userinfo_endpoint' => 'https://openidconnect.googleapis.com/v1/userinfo',
        'jwks_uri' => 'https://www.googleapis.com/oauth2/v3/certs',
        'issuer' => 'https://accounts.google.com',
        'scopes_supported' => %w[openid email profile]
      }.to_json
      stub_response(metadata)

      result = described_class.discover(provider: 'google')

      expect(result[:discovery_url]).to eq('https://accounts.google.com/.well-known/openid-configuration')
      expect(result[:settings]['oauth_authorize_url']).to eq('https://accounts.google.com/o/oauth2/v2/auth')
      expect(result[:settings]['oauth_token_url']).to eq('https://oauth2.googleapis.com/token')
      expect(result[:settings]['oauth_userinfo_url']).to eq('https://openidconnect.googleapis.com/v1/userinfo')
      expect(result[:settings]['oauth_jwks_url']).to eq('https://www.googleapis.com/oauth2/v3/certs')
      expect(result[:settings]['oauth_scope']).to eq('openid email profile')
      expect(result[:settings]['oauth_provider_name']).to eq('Google')
      expect(result[:settings]['oauth_mapping_preset']).to eq('google')
      expect(result[:warnings]).to be_empty
    end

    it 'replaces microsoft tenant placeholders based on options' do
      metadata = {
        'authorization_endpoint' => 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
        'token_endpoint' => 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
        'issuer' => 'https://login.microsoftonline.com/{tenantid}/v2.0',
        'userinfo_endpoint' => 'https://graph.microsoft.com/oidc/userinfo',
        'jwks_uri' => 'https://login.microsoftonline.com/common/discovery/v2.0/keys',
        'end_session_endpoint' => 'https://login.microsoftonline.com/common/oauth2/v2.0/logout',
        'scopes_supported' => %w[openid email profile offline_access]
      }.to_json
      stub_response(metadata)

      result = described_class.discover(provider: 'microsoft', tenant: 'contoso.onmicrosoft.com')

      expect(result[:settings]['oauth_authorize_url']).to eq('https://login.microsoftonline.com/common/oauth2/v2.0/authorize')
      expect(result[:settings]['oauth_expected_issuer']).to eq('https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0')
      expect(result[:settings]['oauth_logout_url']).to eq('https://login.microsoftonline.com/common/oauth2/v2.0/logout')
      expect(result[:settings]['oauth_scope']).to eq('openid email profile offline_access')
      expect(result[:settings]['oauth_provider_name']).to eq('Microsoft Entra ID')
    end

    it 'returns warnings when discovery omits optional endpoints' do
      metadata = {
        'authorization_endpoint' => 'https://id.example.com/authorize',
        'token_endpoint' => 'https://id.example.com/token',
        'scopes_supported' => %w[openid profile]
      }.to_json
      stub_response(metadata)

      result = described_class.discover(discovery_url: 'https://id.example.com/.well-known/openid-configuration')

      expect(result[:settings]['oauth_authorize_url']).to eq('https://id.example.com/authorize')
      expect(result[:settings]['oauth_token_url']).to eq('https://id.example.com/token')
      expect(result[:warnings]).to include(/user info endpoint/i)
      expect(result[:warnings]).to include(/JWKS URL/i)
    end

    it 'raises an error when required endpoints are missing' do
      metadata = { 'token_endpoint' => 'https://id.example.com/token' }.to_json
      stub_response(metadata)

      expect {
        described_class.discover(discovery_url: 'https://id.example.com/.well-known/openid-configuration')
      }.to raise_error(BlessThisRedmineSso::Discovery::Error, /missing required fields/i)
    end
  end
end
