# frozen_string_literal: true

module Kenna
  module 128iid
    module GithubSecretScanning
      class Client
        class ApiError < StandardError; end
        HOST = "https://api.github.com"

        def initialize(username, token)
          auth_token = Base64.strict_encode64("#{username}:#{token}")
          @headers = {
            "content-type": "application/json",
            "Accept": "application/json",
            "Authorization": "Basic #{auth_token}"
          }
        end

        def secret_scanning_alerts(endpoint, page, page_size, state, secret_type, resolution)
          url = +"#{HOST}#{endpoint}?page=#{page}&per_page=#{page_size}"
          url.concat("&state=#{state}") if state.present?
          url.concat("&secret_type=#{secret_type}") if secret_type.present?
          url.concat("&resolution=#{resolution}") if resolution.present?
          response = http_get(url, @headers)
          raise ApiError, "Unable to retrieve alerts, please check credentials or GitHub permissions" unless response

          JSON.parse(response)
        end

        def alert_locations(url)
          response = http_get(url, @headers)
          raise ApiError, "Unable to retrieve alert locations from #{url}." unless response

          JSON.parse(response)
        end
      end
    end
  end
end
