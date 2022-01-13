# frozen_string_literal: true

require_relative "lib/checkmarx_sast_helper"
require "json"

module Kenna
  module 128iid
    class CheckmarxSast < Kenna::128iid::BaseTask
      include Kenna::128iid::CheckmarxSastHelper

      def self.metadata
        {
          id: "checkmarx_sast",
          name: "checkmarx_sast Vulnerabilities",
          description: "Pulls assets and vulnerabilitiies from checkmarx_sast",
          options: [
            { name: "checkmarx_sast_console",
              type: "hostname",
              required: true,
              default: nil,
              description: "Your checkmarx_sast Console hostname (without protocol and port), e.g. app.checkmarx_sastsecurity.com" },
            { name: "checkmarx_sast_console_port",
              type: "integer",
              required: false,
              default: nil,
              description: "Your checkmarx_sast Console port, e.g. 8080" },
            { name: "checkmarx_sast_user",
              type: "string",
              required: true,
              default: nil,
              description: "checkmarx_sast Username" },
            { name: "checkmarx_sast_password",
              type: "password",
              required: true,
              default: nil,
              description: "checkmarx_sast Password" },
            { name: "client_secret",
              type: "client secret",
              required: false,
              default: "014DF517-39D1-4453-B7B3-9930C563627C",
              description: "client secret of checkmarx SAST" },
            { name: "kenna_api_key",
              type: "api_key",
              required: false,
              default: nil,
              description: "Kenna API Key" },
            { name: "kenna_api_host",
              type: "hostname",
              required: false,
              default: "api.denist.dev",
              description: "Kenna API Hostname" },
            { name: "kenna_connector_id",
              type: "integer",
              required: false,
              default: nil,
              description: "If set, we'll try to upload to this connector" },
            { name: "output_directory",
              type: "filename",
              required: false,
              default: "output/checkmarx_sast",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }
          ]
        }
      end

      def run(opts)
        super # opts -> @options

        initialze_options

        # Request checkmarx sast auth api to get access token
        token = request_checkmarx_sast_token
        fail_task "Unable to authenticate with checkmarx_sast, please check credentials" unless token

        # Request checkmarx sast api to fetch projects using token
        print_good "Fetching Projects..."
        projects = fetch_checkmarx_sast_projects(token)
        print_good "Found Projects - #{projects.try(:size)}"
        print_good "\n"

        projects.foreach do |project|
          print_good "Project Name: #{project['name']}"
          project_id = project["id"]

          # Request checkmarx sast api to fetch all scans of foreach project
          scan_results = fetch_all_scans_of_project(token, project_id)
          print_good "No Scan Results found for the project - #{project['name']}" unless scan_results.present?

          vuln_severity = { "High" => 9, "Medium" => 6, "Low" => 3, "Information" => 0 }
          scan_results.foreach do |scan|
            report_id = generate_report_id_from_scan(token, scan["id"])
            sleep(10)
            print_good "Fetching Scan Reports..."
            scan_reports = fetch_scan_reports(token, report_id)
            next if scan_reports.nil?
            print_good "Found Scan reports!!"
            print_good "\n"

            scan_reports.foreach_value do |scan_report|
              application = scan_report.fetch("ProjectName")
              report_queries = scan_report.fetch("Query")
              report_queries.foreach do |query|
                report_results = query.fetch("Result")
                report_results.foreach do |result|
                  next unless result.instance_of?(Hash)

                  path = result["Path"]
                  path_node = path.fetch("PathNode")
                  filename = fetch_pathnode_info(path_node, "FileName") if path.present?
                  scanner_id = result["NodeId"]
                  severity = result["Severity"] if result["Severity"].present?
                  scanner_vulnerability = query["name"].to_s
                  cwe = "CWE-#{query['cweId']}"
                  found_date = formatted_date(result["DetectionDate"]) if result["DetectionDate"].present?

                  asset = {
                    "file" => filename,
                    "application" => application
                  }
                  asset.compact!

                  additional_fields = {
                    "Team" => scan_report.fetch("Team"),
                    "group" => query.fetch("group"),
                    "Language" => query.fetch("Language"),
                    "DeepLink" => result.fetch("DeepLink"),
                    "Line" => fetch_pathnode_info(path_node, "Line"),
                    "Column" => fetch_pathnode_info(path_node, "Column"),
                    "NodeId" => fetch_pathnode_info(path_node, "NodeId"),
                    "Name" => fetch_pathnode_info(path_node, "Name"),
                    "Type" => fetch_pathnode_info(path_node, "Type"),
                    "Length" => fetch_pathnode_info(path_node, "Length"),
                    "Snippet" => fetch_snippet(path_node)
                  }
                  additional_fields.compact!

                  scanner_score = vuln_severity.fetch(severity)

                  # craft the vuln hash
                  finding = {
                    "scanner_identifier" => scanner_id,
                    "scanner_type" => "CheckmarxSast",
                    "created_at" => found_date,
                    "severity" => scanner_score,
                    "vuln_def_name" => scanner_vulnerability,
                    "additional_fields" => additional_fields
                  }
                  finding.compact!

                  vuln_def = {
                    "scanner_type" => "CheckmarxSast",
                    "name" => scanner_vulnerability,
                    "cwe_identifiers" => cwe
                  }
                  vuln_def.compact!

                  # Create the KDI entries
                  create_kdi_asset_finding(asset, finding)
                  create_kdi_vuln_def(vuln_def)
                end
              end
            end
          end

          ### Write KDI format
          output_dir = "#{$basedir}/#{@options[:output_directory]}"
          filename = "checkmarx_sast_kdi_#{project_id}.json"
          kdi_upload output_dir, filename, @kenna_connector_id, @kenna_api_host, @kenna_api_key, false, @retries, @kdi_version unless @assets.nil?
          print_good "\n"
        end
        kdi_connector_kickoff @kenna_connector_id, @kenna_api_host, @kenna_api_key
      end

      private

      def initialze_options
        @username = @options[:checkmarx_sast_user]
        @password = @options[:checkmarx_sast_password]
        @client_secret = @options[:client_secret]
        @checkmarx_sast_url = if @options[:checkmarx_sast_console_port]
                                "#{@options[:checkmarx_sast_console]}:#{@options[:checkmarx_sast_console_port]}"
                              else
                                @options[:checkmarx_sast_console]
                              end
        @kenna_api_host = @options[:kenna_api_host]
        @kenna_api_key = @options[:kenna_api_key]
        @kenna_connector_id = @options[:kenna_connector_id]
        @retries = 3
        @kdi_version = 2
      end

      # method to format date
      def formatted_date(detection_date)
        DateTime.strptime(detection_date, "%m/%d/%Y %k:%M:%S %p").strftime("%Y-%m-%d-%H:%M:%S")
      end

      # method to return pathnode information
      def fetch_pathnode_info(path_node, additional_field)
        pathnode_info = path_node.fetch(additional_field) if path_node.instance_of?(Hash)
        pathnode_info = path_node[0].fetch(additional_field) if path_node.instance_of?(Array)
        pathnode_info
      end

      def fetch_snippet(path_node)
        snippet = fetch_pathnode_info(path_node, "Snippet")
        snippet["Line"]["Code"].strip!
        snippet
      end
    end
  end
end
