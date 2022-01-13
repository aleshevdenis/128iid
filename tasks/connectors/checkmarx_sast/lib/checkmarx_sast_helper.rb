# frozen_string_literal: true

require "json"

module Kenna
  module 128iid
    module CheckmarxSastHelper
      attr_reader :username, :password, :checkmarx_sast_url, :client_id, :client_secret

      # Method for generating token using username & pwd, client ID and secret
      def request_checkmarx_sast_token
        print_debug "Getting Auth Token"
        checkmarx_sast_auth_api_url = "https://#{checkmarx_sast_url}/cxrestapi/auth/identity/connect/token"
        # Retrieve an OAuth access token to be used against Checkmarx SAST API"
        headers = { "content-type" => "application/x-www-form-urlencoded" }
        payload = {
          grant_type: "password",
          scope: "sast_api",
          username: username,
          password: password,
          client_id: "resource_owner_sast_client",
          client_secret: client_secret
        }

        begin
          auth_response = http_post(checkmarx_sast_auth_api_url, headers, payload)
          return unless auth_response

          token = JSON.parse(auth_response)["access_token"]
        rescue JSON::ParserError
          print_error "Unable to process Auth Token response!"
        rescue StandardError => e
          print_error "Failed to retrieve Auth Token #{e.message}"
        end
        token
      end

      # method to get all projects using user credentials
      def fetch_checkmarx_sast_projects(token)
        checkmarx_sast_projects_api_url = "https://#{checkmarx_sast_url}/cxrestapi/projects"
        headers = bearer_token_headers(token)
        auth_response = http_get(checkmarx_sast_projects_api_url, headers)
        return nil unless auth_response

        begin
          project_results = JSON.parse(auth_response.body)
        rescue JSON::ParserError
          print_error "Unable to process Projects response!"
        end
        project_results
      end

      # method to fetch all scans of foreach project
      def fetch_all_scans_of_project(token, project_id)
        print_good "Getting All Scans of Project ID: #{project_id} \n"
        checkmarx_sast_scans_api_url = "https://#{checkmarx_sast_url}/cxrestapi/sast/scans?last=1&scanStatus=Finished&projectId=#{project_id}"
        headers = bearer_token_headers(token)
        auth_response = http_get(checkmarx_sast_scans_api_url, headers)
        return nil unless auth_response

        begin
          scan_results = JSON.parse(auth_response.body)
        rescue JSON::ParserError
          print_error "Unable to process scans response!"
        end
        scan_results
      end

      def generate_report_id_from_scan(token, scan_id)
        sast_report_generation_api_url = "https://#{checkmarx_sast_url}/cxrestapi/reports/sastScan"
        headers = post_bearer_token_headers(token)
        payload = {
          ScanId: scan_id,
          reportType: "XML"
        }
        auth_response = http_post(sast_report_generation_api_url, headers, payload)
        return nil unless auth_response

        begin
          report = JSON.parse(auth_response.body)
        rescue JSON::ParserError
          print_error "Unable to process report generation!"
        end
        report["reportId"]
      end

      def fetch_scan_reports(token, report_id)
        sast_scan_reports_api_url = "https://#{checkmarx_sast_url}/cxrestapi/reports/sastScan/#{report_id}"
        headers = bearer_token_headers(token)
        auth_response = http_get(sast_scan_reports_api_url, headers)
        return nil unless auth_response

        begin
          report = Hash.from_xml(auth_response.body)
        rescue JSON::ParserError
          print_error "Unable to process scan reports!"
        end
        report
      end

      private

      def post_bearer_token_headers(token)
        {
          "accept" => "application/json",
          "Authorization" => "Bearer #{token}",
          "content-type" => "application/x-www-form-urlencoded"
        }
      end
      def bearer_token_headers(token)
        {
          "Content-Type" => "application/json",
          "accept" => "application/json",
          "Authorization" => "Bearer #{token}"
        }
      end
    end
  end
end
