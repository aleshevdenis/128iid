# frozen_string_literal: true

module Kenna
  module 128iid
    module AppScanCloud
      class Client
        class ApiError < StandardError; end

        HOST = "https://cloud.appscan.com"
        def initialize(key_id, key_secret)
          @api = "#{HOST}/api/v2"
          auth_token = login_token(key_id, key_secret)
          @headers = {
            "content-type": "application/json",
            "Accept": "application/json",
            "Authorization": "Bearer #{auth_token}"
          }
        end

        def issues(application_id, skip, top, severities)
          endpoint = "#{@api}/Issues/Application/#{application_id}?$inlinecount=allpages&$skip=#{skip}&$top=#{top}#{severities_filter(severities)}"

          response = http_get(endpoint, @headers)
          raise ApiError, "Unknown error while trying to get issues." unless response

          JSON.parse(response)
        end

        def applications
          endpoint = "#{@api}/Apps"

          response = http_get(endpoint, @headers)
          raise ApiError, "Unknown error while trying to get applications." unless response

          JSON.parse(response)
        end

        private

        def login_token(key_id, key_secret)
          endpoint = "#{@api}/Account/ApiKeyLogin"
          payload = { "KeyId": key_id, "KeySecret": key_secret }.to_json

          response = http_post(endpoint, { "content-type": "application/json" }, payload)
          raise ApiError, "Unable to retrieve /Account/ApiKeyLogin. Please check credentials" unless response

          JSON.parse(response).fetch("Token")
        end

        def severities_filter(severities = [])
          return "" if severities.empty?

          "&$filter=#{severities.map { |severity| "Severity eq '#{severity}'" }.join(' or ')}"
        end
      end
    end
  end
end
