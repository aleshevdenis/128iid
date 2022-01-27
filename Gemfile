# frozen_string_literal: true

source "https://rubygems.org"

# git_source(:github) do |repo_name|
#  repo_name = "#{repo_name}/#{repo_name}" unless repo_name.include?("/")
#  "https://github.com/#{repo_name}.git"
# end

# Only required for file upload types (Guardium and Qualys to Kenna Direct), comment out if unneeded:
# gem 'nokogiri'

gem "activesupport"
gem "addressable"
gem "aws-sdk-guardduty"
gem "aws-sdk-inspector"
gem "json"
gem "json-write-stream"
gem "rest-client"
gem "sanitize"
gem "tty-pager"
gem "httparty"
gem "rexml", ">= 3.2.5"

group :development, :test do
  gem "pry"
  gem "pry-byebug"
  gem "rspec"
  gem "rubocop", "~> 1.25", require: false
  gem "rubocop-github", "~> 0.17"
  gem "rubocop-performance", require: false
  gem "rubocop-rails", require: false
  gem "solargraph", require: false
  gem "timecop"
end
