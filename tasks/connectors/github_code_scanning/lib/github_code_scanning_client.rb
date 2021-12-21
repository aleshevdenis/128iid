# frozen_string_literal: true

module Kenna
  module 128iid
    module GithubCodeScanning
      class Client
        class ApiError < StandardError; end
        HOST = "https://api.github.com"

        def initialize(username, token)
          auth_token = Base64.strict_encode64("#{username}:#{token}")
          @headers = {
            "Accept": "application/vnd.github.v3+json",
            "Authorization": "Basic #{auth_token}"
          }
        end

        def code_scanning_alerts(endpoint, page, page_size, state, tool_name)
          url = +"#{HOST}#{endpoint}?page=#{page}&per_page=#{page_size}"
          url.concat("&state=#{state}") if state.present?
          url.concat("&tool_name=#{tool_name}") if tool_name.present?
          response = http_get(url, @headers)
          raise ApiError, "Unable to retrieve alerts, please check credentials or GitHub permissions" unless response

          JSON.parse(response)
        end
      end
    end
  end
end
