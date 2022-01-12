# frozen_string_literal: true

module Kenna
  module 128iid
    module Sysdig
      class Client
        class ApiError < StandardError; end

        def initialize(host, api_token, page_size)
          @base_path = "https://#{host}"
          @headers = { "Content-Type": "application/json", "Accept": "application/json",
                       "Accept-Encoding": "gzip, deflate, sdch", "Authorization": "Bearer #{api_token}" }
          @page_size = page_size
        end

        def vulnerabilities(severity, days_back, &block)
          return to_enum(__method__, severity, days_back) unless block

          payload = {
            "queryType": "vuln",
            "scopeType": "static",
            "limit": @page_size - 1
          }
          vuln_filter = {}
          vuln_filter["severity"] = severity.join(",") if severity
          vuln_filter["age"] = { "from": (Date.today - days_back).to_datetime.iso8601, "to": Date.today.to_datetime.iso8601 } if days_back.positive?
          payload["vulnQueryFilter"] = vuln_filter

          offset = 0
          loop do
            payload["offset"] = offset
            response = http_post("#{@base_path}/api/scanning/v1/reports", @headers, payload.to_json)
            raise ApiError, "Unable to retrieve vulnerabilities, please check credentials." unless response

            response_hash = JSON.parse(response)
            vulns = response_hash.fetch("imageResponse")
            block.yield(vulns)
            break unless response_hash.fetch("canLoadMore")

            offset += vulns.count
          end
        end
      end
    end
  end
end
