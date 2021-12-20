# frozen_string_literal: true

require_relative "lib/checkmarx_sca_helper"
require "json"

module Kenna
  module 128iid
    class CheckmarxSca < Kenna::128iid::BaseTask
      include Kenna::128iid::CheckmarxScaHelper

      def self.metadata
        {
          id: "checkmarx_sca",
          name: "checkmarx_sca Vulnerabilities",
          description: "Pulls assets and vulnerabilitiies from checkmarx_sca",
          options: [
            { name: "checkmarx_sca_user",
              type: "user",
              required: true,
              default: nil,
              description: "checkmarx_sca Username" },
            { name: "checkmarx_sca_password",
              type: "password",
              required: true,
              default: nil,
              description: "checkmarx_sca Password" },
            { name: "tenant_id",
              type: "string ",
              required: true,
              default: nil,
              description: "tenent id checkmarx SCA" },
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
              default: "output/checkmarx_sca",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }
          ]
        }
      end

      def run(opts)
        super # opts -> @options

        initialze_options

        # Request checkmarx sca auth api to get access token
        token = request_checkmarx_sca_token
        fail_task "Unable to authenticate with checkmarx_sca, please check credentials" unless token

        # Request checkmarx sca api to fetch projects using token
        projects = fetch_checkmarx_sca_projects(token)
        projects.foreach do |project|
          print_good "Project Name: #{project['name']}"

          asset = { "application" => project["name"] }

          # Request checkmarx sca api to fetch all scans of foreach project
          scans = fetch_all_scans_of_project(token, project["id"])
          vulnerabilites = fetch_all_vulns_of_project(token, scans[0]["scanId"])
          vulnerabilites.foreach do |vuln|
            finding = {
              "scanner_identifier" => vuln["id"],
              "scanner_type" => "checkmarx_sca",
              "created_at" => DateTime.parse(scans[0]["createdOn"]).to_time.iso8601,
              "severity" => (vuln["score"] || 0).to_i,
              "triage_state" => vuln["isIgnored"] == false ? "new" : "false_positive",
              "vuln_def_name" => vuln["id"],
              "additional_fields" => {
                "severity" => vuln["severity"],
                "cwe_identifiers" => vuln["cwe"],
                "references" => vuln["references"],
                "isIgnored" => vuln["isIgnored"]
              }
            }

            finding.compact!

            vuln_def = {
              "scanner_type" => "checkmarx_sca",
              "name" => vuln["id"],
              "description" => vuln["description"],
              "solution" => vuln["recommendations"]
            }

            asset["file"] = vuln["packageId"]

            vuln_def["cve_identifiers"] = vuln["cveName"] if vuln["cveName"].present?

            vuln_def.compact!
            create_kdi_asset_finding(asset, finding)
            create_kdi_vuln_def(vuln_def)
          end
          next if vulnerabilites.empty?

          ### Write KDI format
          output_dir = "#{$basedir}/#{@options[:output_directory]}"
          FileUtils.mkdir_p output_dir
          filename = "checkmarx_sca_#{project['name']}.json"
          print_good "Output is available at: #{output_dir}/#{filename}"
          print_good "Attempting to upload to Kenna API"
          kdi_upload output_dir, filename, @kenna_connector_id, @kenna_api_host, @kenna_api_key, false, @retries, @kdi_version
        end
        kdi_connector_kickoff(@kenna_connector_id, @kenna_api_host, @kenna_api_key)
        print_good "\n"
      end

      def initialze_options
        @username = @options[:checkmarx_sca_user]
        @password = @options[:checkmarx_sca_password]
        @tenant_id = @options[:tenant_id]
        @kenna_api_host = @options[:kenna_api_host]
        @kenna_api_key = @options[:kenna_api_key]
        @kenna_connector_id = @options[:kenna_connector_id]
        @kdi_version = 2
      end
    end
  end
end
