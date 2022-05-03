# frozen_string_literal: true

module Kenna
  module 128iid
    module DigitalDefense
      class Client
        class ApiError < StandardError; end

        attr_accessor :endpoint, :headers

        def initialize(host, api_token)
          @endpoint = "#{host}/api/"
          @headers = { "content-type": "application/json", "Authorization": "Token #{api_token}" }
        end

        def get_vulnerabilities(page: 1, count: 25)
          url = URI("https://#{endpoint}scanresults/active/vulnerabilities/")
          payload = {
            page:,
            count:,
            _0_notiin_vuln_active_view_status: "fixed",
            _1_eq_vuln_acceptable_risk: "False",
            _2_eq_vuln_false_positive: "False",
            _3_iin_vuln_severity_ddi: "Critical",
            _4_iin_vuln_severity_ddi: "High",
            _5_iin_vuln_severity_ddi: "Low"
          }

          url.query = URI.encode_www_form(payload)
          response = http_get(url.to_s, headers)
          raise ApiError, "Unable to retrieve last scheduled scan, please check credentials" unless response

          JSON.parse(response)
        end

        def get_vulndictionary(page)
          url = URI("https://#{endpoint}vulndictionary")
          payload = { include_details: true, page:, count: 5000 }

          url.query = URI.encode_www_form(payload)

          print_debug url.to_s
          response = http_get(url.to_s, headers)
          raise ApiError, "Unable to retrieve scan." unless response

          JSON.parse(response)
        end
      end
    end
  end
end
