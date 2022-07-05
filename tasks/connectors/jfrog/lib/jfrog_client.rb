# frozen_string_literal: true

module Kenna
  module 128iid
    module JFrog
      class JFrogClient
        class ApiError < StandardError; end

        def self.url(hostname)
          return hostname if hostname.downcase.start_with?("http")

          "https://#{hostname}"
        end

        def initialize(hostname, api_user, api_token)
          auth_token = Base64.strict_encode64("#{api_user}:#{api_token}")
          @endpoint = "#{self.class.url(hostname)}/xray/api"
          @headers = {
            "content-type": "application/json",
            "Accept": "application/json",
            "Authorization": "Basic #{auth_token}"
          }
        end

        def execute_vulns_report(repositories, severities, days_back, report_timeout)
          sleep_seconds = 5
          elapsed_seconds = 0
          report_complete = false
          report_id = create_report(repositories, severities, days_back)
          until report_complete || elapsed_seconds >= report_timeout
            print "Waiting for report by #{sleep_seconds} seconds ..."
            sleep(sleep_seconds)
            report_complete = completed_report?(report_id)
            elapsed_seconds += sleep_seconds
          end
          print "Report timeout. Can not obtain the report after #{report_timeout} seconds. Try incrementing the report_timeout parameter." unless report_complete
          report_id if report_complete
        end

        def vulnerabilities_report_content(vulns_report_id, page_num, num_of_rows)
          response = http_post("#{@endpoint}/v1/reports/vulnerabilities/#{vulns_report_id}?direction=asc&page_num=#{page_num}&num_of_rows=#{num_of_rows}&order_by=impacted_artifact", @headers, "")
          raise ApiError, "Unable to to retrieve vulnerabilities report content." unless response

          JSON.parse(response)
        end

        private

        def create_report(repositories, severities, days_back)
          payload = create_report_payload(repositories, severities, days_back)
          response = http_post("#{@endpoint}/v1/reports/vulnerabilities", @headers, payload)
          raise ApiError, "Unable to create JFrog vulnerabilities report, please check credentials" unless response

          response_data = JSON.parse(response)
          response_data["report_id"]
        end

        def create_report_payload(repositories, severities, days_back)
          {
            name: "kenna-connector-vulns-report-#{SecureRandom.uuid}",
            resources: {
              repositories: repositories.map { |repo| { "name": repo } }
            },
            filters: {
              severities:,
              scan_date: {
                start: (Date.today - days_back).to_datetime.iso8601,
                end: DateTime.now.iso8601
              }
            }
          }.to_json
        end

        def completed_report?(report_id)
          response = http_get("#{@endpoint}/v1/reports/#{report_id}", @headers)
          response_data = JSON.parse(response)
          response_data["status"] == "completed"
        end
      end
    end
  end
end
