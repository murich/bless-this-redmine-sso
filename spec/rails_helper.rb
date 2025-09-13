# frozen_string_literal: true

require_relative 'spec_helper'

begin
  # Load Redmine's environment when run from the plugin directory
  require File.expand_path('../../../config/environment', __dir__)
rescue LoadError
  warn 'Redmine environment not found. Please run specs from Redmine root.'
end

# Define missing encoding constant for Ruby >= 3.2
module ActionView
  ENCODING_FLAG = '#.*coding[:=]\\s*(\\S+)[ \t]*' unless const_defined?(:ENCODING_FLAG)
end

if defined?(Rails)
  begin
    require 'rspec/rails'
  rescue LoadError
    warn 'rspec-rails is not available. Please bundle install to run specs.'
  end
else
  warn 'Rails environment not loaded. RSpec Rails features unavailable.'
end

# Additional setup for Redmine plugin specs could be placed here.
