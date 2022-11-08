# frozen_string_literal: true

module Kenna
  module 128iid
    module CobaltioHelper
      @@assets = []

      def cobalt_get_assets(api_token, org_token)
        print "Getting list of assets"
        cobalt_assets_api = "https://api.cobalt.io/assets?limit=1000"
        headers = cobalt_get_req_headers(api_token, org_token)

        response = http_get(cobalt_assets_api, headers)
        return nil unless response

        begin
          json = JSON.parse(response.body)
        rescue JSON::ParserError
          print_error "Unable to process response!"
        end

        @@assets = json["data"]
      end

      def cobalt_get_asset(api_token, org_token, asset_id)
        cobalt_get_assets(api_token, org_token) if @@assets.length == 0
        @@assets.find { |entry| entry["resource"]["id"] == asset_id }
      end

      def cobalt_get_findings(api_token, org_token)
        print "Getting list of findings"
        cobalt_findings_api = "https://api.cobalt.io/findings?limit=1000"
        headers = cobalt_get_req_headers(api_token, org_token)

        response = http_get(cobalt_findings_api, headers)
        return nil unless response

        begin
          json = JSON.parse(response.body)
        rescue JSON::ParserError
          print_error "Unable to process response!"
        end

        json["data"]
      end

      def cobalt_get_req_headers(api_token, org_token)
        headers = { "accept" => "application/vnd.cobalt.v1+json",
                    "Authorization" => "Bearer #{api_token}",
                    "X-Org-Token" => org_token }
      end

      def cobalt_get_created(finding_log)
        created_entry = finding_log.find { |entry| entry["action"] == "created" }
        return nil unless created_entry
        created_entry.fetch("timestamp") if created_entry
      end

      def cobalt_exclude_finding(finding_obj)
        state = finding_obj["resource"]["state"]
        import_states = ["need_fix", "wont_fix", "valid_fix", "check_fix", "carried_over"]
        not import_states.include? state
      end
    end
  end
end
