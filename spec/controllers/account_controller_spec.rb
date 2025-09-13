# frozen_string_literal: true

require_relative '../rails_helper'

if defined?(AccountController) && defined?(Setting)
  RSpec.describe AccountController, type: :controller do
    describe 'GET #logout' do
      let(:logout_url) { 'https://example.com/logout' }

      context 'when OAuth is enabled and logout URL is configured' do
        before do
          Setting.plugin_bless_this_redmine_sso = {
            'oauth_enabled' => '1',
            'oauth_logout_url' => logout_url
          }
        end

        context 'without oauth session flag' do
          it 'does not redirect to the SSO logout URL' do
            get :logout
            expect(response).not_to redirect_to(logout_url)
          end
        end

        context 'with oauth session flag' do
          before { session[:oauth_logged_in] = true }

          it 'redirects to the SSO logout URL' do
            get :logout
            expect(response).to redirect_to(logout_url)
          end
        end
      end

      context 'when OAuth is disabled' do
        before do
          Setting.plugin_bless_this_redmine_sso = {
            'oauth_enabled' => '0',
            'oauth_logout_url' => logout_url
          }
        end

        it 'does not redirect to the SSO logout URL' do
          get :logout
          expect(response).not_to redirect_to(logout_url)
        end
      end
    end
  end
else
  RSpec.describe 'AccountController', type: :controller do
    it 'is skipped because AccountController is not defined' do
      skip 'AccountController not available. Run specs within a Redmine environment.'
    end
  end
end
