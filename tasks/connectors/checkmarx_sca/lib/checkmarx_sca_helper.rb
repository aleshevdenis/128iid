# frozen_string_literal: true

require "json"

module Kenna
  module 128iid
    module CheckmarxScaHelper
      attr_reader :username, :password, :tenant_id

      # Method for generating token using username & pwd , client ID and secret
      def request_checkmarx_sca_token
        print_debug "Getting Auth Token"
        checkmarx_sca_auth_api_url = "https://platform.checkmarx.net/identity/connect/token"
        # Retrieve an OAuth access token to be used against Checkmarx SAST API"
        headers = { "content-type" => "application/x-www-form-urlencoded" }
        payload = {
          grant_type: "password",
          scope: "sca_api",
          username: username,
          password: password,
          client_id: "sca_resource_owner",
          acr_values: "Tenant:#{tenant_id}"
        }

        begin
          auth_response = http_post(checkmarx_sca_auth_api_url, headers, payload)
          return unless auth_response

          token = JSON.parse(auth_response)["access_token"]
          print_debug token.to_s
          token
        rescue JSON::ParserError
          print_error "Unable to process Auth Token response!"
        rescue StandardError => e
          print_error "Failed to retrieve Auth Token #{e.message}"
        end
      end

      # method to get all projects using user credentials
      def fetch_checkmarx_sca_projects(token)
        print_good "Getting Projects \n"
        checkmarx_sast_projects_api_url = "https://api-sca.checkmarx.net/risk-management/projects"
        headers = {
          "Content-Type" => "application/json",
          "accept" => "application/json",
          "Authorization" => "Bearer #{token}"
        }
        auth_response = http_get(checkmarx_sast_projects_api_url, headers)
        return nil unless auth_response

        begin
          project_results = JSON.parse(auth_response.body)
        rescue JSON::ParserError
          print_error "Unable to process Projects response!"
        end
        project_results
      end

      def fetch_all_scans_of_project(token, project_id)
        print_good "\n"
        print_good "Getting All vulnerabilities of ScanId: #{project_id} \n"
        checkmarx_sca_all_scans_api_url = "https://api-sca.checkmarx.net/risk-management/scans?projectId=#{project_id}"
        headers = {
          "Content-Type" => "application/json",
          "accept" => "application/json",
          "Authorization" => "Bearer #{token}"
        }
        auth_response = http_get(checkmarx_sca_all_scans_api_url, headers)
        return nil unless auth_response

        begin
          scan_results = JSON.parse(auth_response.body)
          print_good "Scan Results: \n"
          print_good scan_results.to_s
        rescue JSON::ParserError
          print_error "Unable to process scans response!"
        end
        scan_results
      end

      # method to fetch all vuln of foreach project

      def fetch_all_vulns_of_project(token, scan_id)
        print_good "\n"
        print_good "Getting All vulnerabilities of ScanId: #{scan_id} \n"
        checkmarx_sca_vulnerabilites_api_url = "https://api-sca.checkmarx.net/risk-management/risk-reports/#{scan_id}/vulnerabilities"
        headers = {
          "Content-Type" => "application/json",
          "accept" => "application/json",
          "Authorization" => "Bearer #{token}"
        }
        auth_response = http_get(checkmarx_sca_vulnerabilites_api_url, headers)
        return nil unless auth_response

        begin
          vulns_results = JSON.parse(auth_response.body)
          print_good "Scan Results: \n"
          print_good vulns_results.to_s
        rescue JSON::ParserError
          print_error "Unable to process scans response!"
        end
        vulns_results
      end
    end
  end
end
