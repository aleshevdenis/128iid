# frozen_string_literal: true

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

        def initialize(api_key, app_name)
          @api_key  = api_key
          @app_name = app_name
          @headers  = { "Content-Type": "application/json", "X-Api-Key": api_key.to_s }
        end

        def receive_app
          receive_apps["data"].detect { |issue| issue["name"] == @app_name }
        end

        def receive_vulns(app_id, filters, page_number, page_size)
          response = http_post("#{HOST}/ias/v1/search?size=#{page_size}&&index=#{page_number}", @headers, receive_query(app_id, filters))

          raise ApiError, "Unable to retrieve vulnerabilities, please check credentials." unless response

          JSON.parse(response)
        end

        def receive_module(module_id)
          response = http_get("#{HOST}/ias/v1/modules/#{module_id}", @headers)

          raise ApiError, "Unable to retrieve modules, please check credentials." unless response

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
          response = http_get("#{HOST}/ias/v1/apps", @headers)

          raise ApiError, "Unable to retrieve applications, please check credentials." unless response

          JSON.parse(response)
        end
      end
    end
  end
end
