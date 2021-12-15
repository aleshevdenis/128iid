# frozen_string_literal: true

module Kenna
  module 128iid
    module QualysWasHelper
      attr_reader :qualys_was_domain, :qualys_was_api_version_url, :base_url, :score

      def qualys_was_get_token(username, password)
        auth_details = "#{username}:#{password}"
        Base64.encode64(auth_details)
      end

      def qualys_was_get_webapp_findings(token, page_size, page)
        # print_good "Getting Webapp Findings For #{webapp_id} \n"
        qualys_was_auth_api = "https://#{base_url}search/was/finding"

        @headers = {
          "Content-Type" => "application/json",
          "accept" => "application/json",
          "Authorization" => "Basic #{token}"
        }

        offset = page == 1 ? 1 : (page * page_size) + 1
        print_debug "Fetching Page = #{page}"
        payload = {
          "ServiceRequest": {
            "preferences": {
              "verbose": "true",
              "limitResults": page_size,
              "startFromOffset": offset
            },
            "filters": {
            }
          }
        }

        if score.present?
          payload[:ServiceRequest][:filters]["Criteria"] = {
            "field": "severity",
            "operator": "GREATER",
            "value": score.to_i
          }
        end

        auth_response = http_post(qualys_was_auth_api, @headers, payload.to_json)
        return nil if auth_response["ServiceResponse"]["responseCode"] == "INVALID_REQUEST"

        begin
          res = JSON.parse(auth_response.body)
        rescue JSON::ParserError
          print_error "Unable to process findings response!"
        end

        res
      end

      def qualys_was_get_vuln(qids, token)
        print_good "Getting VULN For Qids for findings \n"
        qualys_was_auth_api = URI("https://#{qualys_was_domain}/api/2.0/fo/knowledge_base/vuln/")
        @headers = {
          "Content-Type" => "application/json",
          "accept" => "application/json",
          "Authorization" => "Basic #{token}",
          "X-Requested-With" => "QualysPostman"
        }

        payload = {
          "action" => "list",
          "ids" => qids.join(",")
        }

        qualys_was_auth_api.query = URI.encode_www_form(payload)
        auth_response = http_get(qualys_was_auth_api.to_s, @headers)
        return nil unless auth_response

        begin
          response = Hash.from_xml(auth_response.body).to_json
        rescue JSON::ParserError
          print_error "Unable to process XML response!"
        end
        response
      end
    end
  end
end
