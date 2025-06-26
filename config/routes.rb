Rails.application.routes.draw do
  get '/oauth/authorize', to: 'oauth#authorize'
  get '/oauth/callback', to: 'oauth#callback'
end