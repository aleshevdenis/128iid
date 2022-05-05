# frozen_string_literal: true

module Kenna
  module 128iid
    module CarbonBlack
      class Client
        class ApiError < StandardError; end

        def initialize(host, api_id, api_secret_key, org_key, page_size)
          hostname = host.start_with?("http") ? host : "https://#{host}"
          @base_path = "#{hostname}/vulnerability/assessment/api/v1/orgs/#{org_key}"
          @page_size = page_size
          @headers = {
            "Content-type": "application/json",
            "Accept": "application/json",
            "X-Auth-Token": "#{api_secret_key}/#{api_id}"
          }
        end

        def vulnerable_devices(device_types, &)
          endpoint = "#{@base_path}/devices/vulnerabilities/summary/_search"
          filters = { device_type: { value: device_types, operator: "IN" } } if device_types
          paginated(endpoint, filters, &)
        end

        def device_vulnerabilities(device_id, severities, &)
          endpoint = "#{@base_path}/devices/#{device_id}/vulnerabilities/_search"
          filters = { severity: { value: severities, operator: "IN" } } if severities
          paginated(endpoint, filters, &)
        end

        private

        def paginated(endpoint, filters = {}, &block)
          return to_enum(__method__, endpoint, filters) unless block

          offset = 0
          loop do
            response = http_post(endpoint, @headers, { start: offset, rows: @page_size, criteria: filters }.to_json)
            raise ApiError, "Unable to retrieve #{endpoint}, please check credentials" unless response

            response_hash = JSON.parse(response)
            num_found = response_hash.fetch("num_found")
            results = response_hash.fetch("results")
            block.yield(results, num_found, offset)
            break if results.count < @page_size

            offset += @page_size
          end
        end
      end
    end
  end
end
