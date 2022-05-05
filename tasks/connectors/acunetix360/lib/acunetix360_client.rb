# frozen_string_literal: true

module Kenna
  module 128iid
    module Acunetix360
      class Acunetix360Client
        class ApiError < StandardError; end

        HOST = "https://online.acunetix360.com"
        def initialize(user_id, token)
          auth_token = Base64.strict_encode64("#{user_id}:#{token}")
          @endpoint = "#{HOST}/api/1.0"
          @headers = {
            "content-type": "application/json",
            "Accept": "application/json",
            "Authorization": "Basic #{auth_token}"
          }
        end

        def get_last_scan_vulnerabilities(schedule_id)
          id = get_last_scan_id(schedule_id)
          return unless id

          response = http_get(get_vulnerabilities_url(id), @headers)
          raise ApiError, "Unknown error while trying to get vulnerabilities." unless response

          JSON.parse(response)
        end

        private

        def get_last_scan_id(schedule_id)
          found = nil
          page = 1
          loop do
            response = http_get(list_scheduled_url(page), @headers)
            raise ApiError, "Unable to retrieve scheduled scans, please check credentials." unless response

            scheduled_scan_result = JSON.parse(response)
            found = scheduled_scan_result["List"].detect { |scheduled_scan| scheduled_scan["Id"] == schedule_id }
            break if found || scheduled_scan_result["IsLastPage"]

            page += 1
          end
          if found
            found["LastExecutedScanTaskId"]
          else
            print_error "Not found scheduled scan with ID #{schedule_id}"
            nil
          end
        end

        def list_scheduled_url(page)
          fill_params("#{@endpoint}/scans/list-scheduled?page=:page", page:)
        end

        def get_vulnerabilities_url(id)
          fill_params("#{@endpoint}/scans/report?id=:id&format=Json&type=Vulnerabilities", id:)
        end

        def fill_params(params_string, options)
          options.inject(params_string) { |string, (key, value)| string.gsub(key.inspect, value.to_s) }
        end
      end
    end
  end
end
