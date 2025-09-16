# frozen_string_literal: true

require 'json'
require 'net/http'
require 'uri'

begin
  require 'active_support/core_ext/object/blank'
rescue LoadError
  # ActiveSupport is provided by Redmine but the plugin can still operate in
  # test environments where it is unavailable.
  class Object
    def blank?
      respond_to?(:empty?) ? !!empty? : !self
    end unless method_defined?(:blank?)

    def presence
      blank? ? nil : self
    end unless method_defined?(:presence)
  end
end

module BlessThisRedmineSso
  class Discovery
    class Error < StandardError; end

    DEFAULT_SCOPE = 'openid email profile'
    DESIRED_SCOPES = %w[openid email profile offline_access].freeze

    PROVIDERS = {
      'google' => {
        name: 'Google',
        discovery_url: 'https://accounts.google.com/.well-known/openid-configuration',
        scope: 'openid email profile',
        mapping_preset: 'google'
      },
      'microsoft' => {
        name: 'Microsoft Entra ID',
        discovery_url: lambda { |options|
          tenant = (options[:tenant] || options[:microsoft_tenant]).to_s.strip
          tenant = 'common' if tenant.empty?
          "https://login.microsoftonline.com/#{tenant}/v2.0/.well-known/openid-configuration"
        },
        scope: 'openid email profile offline_access User.Read',
        mapping_preset: 'microsoft',
        after: lambda do |settings, metadata, options|
          tenant = (options[:tenant] || options[:microsoft_tenant]).to_s.strip
          tenant = 'common' if tenant.empty?
          issuer = metadata['issuer'].to_s
          unless issuer.empty?
            settings['oauth_expected_issuer'] = issuer.gsub('{tenantid}', tenant).gsub('{tenant}', tenant)
          end
        end
      },
      'casdoor' => {
        name: 'Casdoor',
        discovery_url: lambda do |options|
          base = (options[:base_url] || options[:casdoor_base_url]).to_s.strip
          raise Error, 'Casdoor base URL is required (e.g., https://door.casdoor.com)' if base.empty?

          base = "https://#{base}" unless base.match?(%r{^https?://}i)
          base = base.chomp('/')
          "#{base}/.well-known/openid-configuration"
        end,
        scope: 'openid email profile',
        mapping_preset: 'generic'
      }
    }.freeze

    class << self
      def discover(provider: nil, discovery_url: nil, **raw_options)
        provider_key = provider.to_s.strip
        provider_key = nil if provider_key.empty?
        provider_info = provider_key ? PROVIDERS[provider_key] : nil
        raise Error, "Unknown provider '#{provider}'" if provider_key && provider_info.nil?

        options = symbolize_keys(raw_options)

        url = build_discovery_url(provider_info, discovery_url, options)
        raise Error, 'Discovery URL is required' if url.blank?

        metadata = fetch_metadata(url)

        defaults = provider_defaults(provider_info)
        settings = defaults.merge(map_metadata(metadata))
        apply_provider_overrides!(settings, provider_info, metadata, options)
        ensure_scope!(settings, provider_info)

        warnings = build_warnings(settings)

        {
          settings: settings,
          warnings: warnings,
          discovery_url: url,
          provider: provider_key,
          metadata: metadata
        }
      end

      private

      def symbolize_keys(hash)
        hash.each_with_object({}) do |(key, value), result|
          sym_key = key.respond_to?(:to_sym) ? key.to_sym : key
          result[sym_key] = value
        end
      end

      def build_discovery_url(provider_info, explicit_url, options)
        explicit = explicit_url.to_s.strip
        return explicit unless explicit.empty?

        return '' unless provider_info

        url = provider_info[:discovery_url]
        url = url.call(options) if url.respond_to?(:call)
        url.to_s.strip
      end

      def fetch_metadata(url)
        uri = URI.parse(url)
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = (uri.scheme == 'https')
        http.open_timeout = 5
        http.read_timeout = 5

        request = Net::HTTP::Get.new(uri)
        request['Accept'] = 'application/json'
        response = http.request(request)

        code = response.code.to_i
        raise Error, "Discovery request failed with HTTP #{code}" if code >= 400

        begin
          JSON.parse(response.body)
        rescue JSON::ParserError => e
          raise Error, "Discovery response contained invalid JSON: #{e.message}"
        end
      rescue SocketError, Errno::ECONNREFUSED, Errno::EHOSTUNREACH => e
        raise Error, "Failed to connect to discovery endpoint: #{e.message}"
      end

      def map_metadata(metadata)
        settings = {}
        assign_if_present(settings, 'oauth_authorize_url', metadata['authorization_endpoint'])
        assign_if_present(settings, 'oauth_token_url', metadata['token_endpoint'])
        assign_if_present(settings, 'oauth_userinfo_url', metadata['userinfo_endpoint'])
        assign_if_present(settings, 'oauth_expected_issuer', metadata['issuer'])
        assign_if_present(settings, 'oauth_jwks_url', metadata['jwks_uri'] || metadata['jwks_url'])
        logout = metadata['end_session_endpoint'] || metadata['end_session_url'] || metadata['logout_endpoint'] || metadata['frontchannel_logout_url']
        assign_if_present(settings, 'oauth_logout_url', logout)

        scopes = Array(metadata['scopes_supported']).map(&:to_s)
        unless scopes.empty?
          normalized = normalize_scopes(scopes)
          settings['oauth_scope'] = normalized unless normalized.empty?
        end

        required = %w[oauth_authorize_url oauth_token_url]
        missing = required.select { |key| settings[key].to_s.strip.empty? }
        raise Error, "Discovery document is missing required fields: #{missing.join(', ')}" if missing.any?

        settings
      end

      def provider_defaults(info)
        return {} unless info

        defaults = {}
        defaults['oauth_provider_name'] = info[:name] if info[:name]
        defaults['oauth_scope'] = info[:scope] if info[:scope]
        defaults['oauth_mapping_preset'] = info[:mapping_preset] if info[:mapping_preset]
        defaults
      end

      def apply_provider_overrides!(settings, info, metadata, options)
        return unless info && info[:after].respond_to?(:call)

        info[:after].call(settings, metadata, options)
      end

      def ensure_scope!(settings, provider_info)
        scope = settings['oauth_scope'].to_s.strip
        if scope.empty?
          provider_scope = provider_info && provider_info[:scope]
          scope = provider_scope.to_s.strip
        end
        scope = DEFAULT_SCOPE if scope.empty?
        settings['oauth_scope'] = scope
      end

      def build_warnings(settings)
        warnings = []
        if settings['oauth_userinfo_url'].to_s.strip.empty?
          warnings << 'Discovery document did not include a user info endpoint. Please fill it manually.'
        end
        if settings['oauth_jwks_url'].to_s.strip.empty?
          warnings << 'JWKS URL was not provided by discovery. Required for validating RS256 ID tokens.'
        end
        warnings
      end

      def assign_if_present(settings, key, value)
        str = value.to_s.strip
        settings[key] = str unless str.empty?
      end

      def normalize_scopes(scopes)
        normalized = scopes.map { |scope| scope.split }.flatten
        normalized = normalized.map { |scope| scope.strip }.reject(&:empty?)

        selected = DESIRED_SCOPES.select do |desired|
          normalized.any? { |scope| scope.casecmp(desired).zero? }
        end

        selected.join(' ')
      end
    end
  end
end
