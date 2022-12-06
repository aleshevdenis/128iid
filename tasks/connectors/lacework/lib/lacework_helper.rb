# frozen_string_literal: true

require "net/http"
require "uri"

module Kenna
  module 128iid
    module LaceworkHelper
      MAX_ATTEMPTS = 3

      def generate_temporary_lacework_api_token(account, api_key, api_secret)
        uri = URI.parse("https://#{account}.lacework.net/api/v2/access/tokens")

        request = Net::HTTP::Post.new(uri)
        request.content_type = "application/json"
        request["X-LW-UAKS"] = api_secret.to_s
        request.body = JSON.dump({
                                   "keyId" => api_key.to_s,
                                   "expiryTime" => 86_400
                                 })

        req_options = {
          use_ssl: uri.scheme == "https"
        }

        response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
          http.request(request)
        end

        if response.code != "201"
          print_debug response.message
          return nil
        end

        JSON.parse(response.body)["token"]
      end

      def lacework_post(url:, body:, api_token:)
        uri = URI.parse(url)

        request = Net::HTTP::Post.new(uri)
        request.content_type = "application/json"
        request["Authorization"] = "Bearer #{api_token}"
        request.body = body

        req_options = {
          use_ssl: uri.scheme == "https"
        }

        response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
          http.request(request)
        end

        if response.code == "204"
          print_error "Lacework API returned HTTP code 204: no results found"
          return []
        elsif response.code != "200"
          print_error "Lacework API returned HTTP code #{response.code}:"
          print_error response.message
          return []
        end

        hsh = JSON.parse(response.body)
        data = hsh["data"]

        total_records = hsh.dig("paging", "totalRows") || 0
        print_good "Retrieved #{data.count} of #{total_records} records"

        while (url_next_page = hsh.dig("paging", "urls", "nextPage"))
          hsh = lacework_get(url: url_next_page, api_token:)
          return data if hsh.nil?

          data += (hsh["data"] || [])
          print_good "Retrieved #{data.count} records"
        end

        print_good "Done!"

        data
      end

      def lacework_get(url:, api_token:)
        uri = URI.parse(url)

        request = Net::HTTP::Get.new(uri)
        request.content_type = "application/json"
        request["Authorization"] = "Bearer #{api_token}"

        req_options = {
          use_ssl: uri.scheme == "https"
        }

        response = Net::HTTP.start(uri.hostname, uri.port, req_options) do |http|
          http.request(request)
        end

        if response.code != "200"
          print_error "Lacework API returned HTTP code #{response.code}:"
          print_error response.message
          return nil
        end

        JSON.parse(response.body)
      end

      def lacework_list_cves_v2(account, temp_api_token)
        # See: https://docs.lacework.com/api/v2/docs/#tag/Vulnerabilities/paths/~1api~1v2~1Vulnerabilities~1Hosts~1search/post

        url = "https://#{account}.lacework.net/api/v2/Vulnerabilities/Hosts/search"

        # Without the vulnId filter you get all of a host's packages even if they don't have vulns
        request_body = %(
          {
            "filters": [
              {
                "field": "vulnId",
                "expression": "rlike",
                "value": "CVE.*"
              }
            ]
          }
        )
        lacework_post(url:, body: request_body, api_token: temp_api_token)
      end
    end
  end
end
