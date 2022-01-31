# frozen_string_literal: true

require "pry"

module Kenna
  module 128iid
    module InsightAppSec
      class Client
        class ApiError < StandardError; end

        FILTERS_NAME_MAPPING = {
          "severity" => "vulnerability.severity",
          "status" => "vulnerability.status"
        }.freeze
        HOST = "https://us.api.insight.rapid7.com"

        def initialize(api_key)
          @api_key = api_key
        end

        def get_app_by_name(app_name)
          apps = receive_apps
          apps["data"].detect { |issue| issue["name"] == app_name }
        end

        def get_vulns(app_id, filters, page_number, page_size)
          response = http_post("#{HOST}/ias/v1/search?size=#{page_size}&&index=#{page_number}", headers(@api_key), receive_query(app_id, filters))

          raise ApiError, "Unable to retrieve submissions, please check credentials." unless response

          JSON.parse(response)
        end

        def get_module(module_id)
          response = http_get("#{HOST}/ias/v1/modules/#{module_id}", headers(@api_key))

          raise ApiError, "Unable to retrieve submissions, please check credentials." unless response

          JSON.parse(response)
        end

        private

        def receive_query(app_id, filters)
          query_line = {
            "query": "vulnerability.app.id = '#{app_id}'",
            "type": "VULNERABILITY"
          }

          filters.empty? ? query_line : query_line[:query] += " && #{formatting_query(filters)}"

          query_line.to_json
        end

        def formatting_query(filters)
          filters.map do |key, val|
            "(#{val.map { |v| "#{FILTERS_NAME_MAPPING[key]} = '#{v}'" }.join(' || ')})"
          end.join(" && ")
        end

        def receive_apps
          response = http_get("#{HOST}/ias/v1/apps", headers(@api_key))

          raise ApiError, "Unable to retrieve submissions, please check credentials." unless response

          JSON.parse(response)
        end

        def headers(api_key)
          { "Content-Type": "application/json", "X-Api-Key": api_key.to_s }
        end
      end
    end
  end
end
