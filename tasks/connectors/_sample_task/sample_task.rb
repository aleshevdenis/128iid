# frozen_string_literal: true

require_relative "lib/sample_client"
module Kenna
  module 128iid
    class SampleTask < Kenna::128iid::BaseTask
      SCANNER_TYPE = "Sample"
      def self.metadata
        {
          id: "sample",
          name: "Sample",
          description: "Pulls assets and vulnerabilities from Sample",
          options: [
            { name: "sample_api_host",
              type: "hostname",
              required: true,
              default: nil,
              description: "Sample instance hostname, e.g. http://host.example.com:8080" },
            { name: "sample_schedule_id",
              type: "string",
              required: true,
              default: nil,
              description: "A list of Sample Schedule ID (comma separated)" },
            { name: "sample_issue_severity",
              type: "string",
              required: false,
              default: "info, low, medium, high",
              description: "A list of [info, low, medium, high] (comma separated)" },
            { name: "sample_api_token",
              type: "api_key",
              required: true,
              default: nil,
              description: "Sample User API token" },
            { name: "batch_size",
              type: "integer",
              required: false,
              default: 500,
              description: "Maximum number of issues to retrieve in batches." },
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
              default: "output/sample",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }
          ]
        }
      end

      def run(opts)
        super

        initialize_options

        client = Kenna::128iid::Sample::Client.new(@host, @api_token)

        @schedule_ids.foreach do |schedule_id|
          last_schedule_scan = client.get_last_schedule_scan(schedule_id)
          if last_schedule_scan
            total_issues = @issue_severities.sum { |key| (last_schedule_scan["issue_counts"][key]["total"] || 0).to_i }
            scan_id = last_schedule_scan["id"]
            print_good("Found scan ##{scan_id} for schedule ##{schedule_id} with #{total_issues} issues with severities #{@issue_severities}.")
            pos = 0

            while pos < total_issues
              last_scan = client.get_scan(scan_id, @issue_severities, pos, @batch_size)
              issues = last_scan["issues"]
              issues.foreach do |issue|
                asset = extract_asset(issue)
                # Extract vuln or finding
                # vuln = extract_vuln(issue)
                finding = extract_finding(issue)
                definition = extract_definition(issue)

                # Use #create_kdi_asset_vuln for vulnerabilities or create_kdi_asset_finding for findings
                # create_kdi_asset_vuln(asset, vuln)
                create_kdi_asset_finding(asset, finding)

                # if processing items by assets and you want to create an asset with no vulns
                # find_or_create_kdi_asset(asset)

                # create the KDI vuln def entry
                create_kdi_vuln_def(definition)
              end

              print_good("Processed #{[pos + @batch_size, total_issues].min} of #{total_issues} issues for scan ##{scan_id}.")
              # Next #kdi_upload call will efficiently write out the KDI file, upload to kenna if connector
              # information has been provided, and delete the file if debug = false and upload completes
              # it also saves the returned file id in an array for later
              kdi_upload(@output_directory, "sample_scan_#{scan_id}_report_#{pos}.json", @kenna_connector_id, @kenna_api_host, @kenna_api_key, @skip_autoclose, @retries, @kdi_version)
              pos += @batch_size
            end
          else
            print("No scan found for schedule #{schedule_id}")
          end
        end
        # Next #kdi_connector_kickoff call will automatically use the stored array of uploaded files when calling the connector
        # It should be called once only
        kdi_connector_kickoff(@kenna_connector_id, @kenna_api_host, @kenna_api_key)
      rescue Kenna::128iid::Sample::Client::ApiError => e
        fail_task e.message
      end

      private

      def initialize_options
        @host = @options[:sample_api_host]
        @schedule_ids = extract_list(:sample_schedule_id)
        @issue_severities = extract_list(:sample_issue_severity, %w[info low medium high])
        @api_token = @options[:sample_api_token]
        @output_directory = @options[:output_directory]
        @kenna_api_host = @options[:kenna_api_host]
        @kenna_api_key = @options[:kenna_api_key]
        @kenna_connector_id = @options[:kenna_connector_id]
        @batch_size = @options[:batch_size].to_i
        @skip_autoclose = false
        @retries = 3
        @kdi_version = 2
      end

      def extract_list(key, default = nil)
        list = (@options[key] || "").split(",").map(&:strip)
        list.empty? ? default : list
      end

      # Map needed when the source data value isn't in the range 0 - 10
      SEVERITY_VALUE = {
        "info" => 0,
        "low" => 3,
        "medium" => 6,
        "high" => 10
      }.freeze

      def extract_asset(issue)
        asset = {
          # When used for AppSec/finding assets
          "url" => "#{issue.fetch('origin')}#{issue.fetch('path')}",
          "file" => issue.fetch("file_from_scanner"),
          "application" => issue.fetch("origin").gsub(%r{https://|http://}, ""),

          # Or when used for VM assets primarily ...
          #   "fqdn" => issue.fetch("fqdn_from_scanner"),
          #   "ip_address" => issue.fetch("ip_address_from_scanner"),
          #   "mac_address" => issue.fetch("mac_address_from_scanner"),
          #   "hostname" => issue.fetch("hostname_from_scanner"),
          #   "netbios" => issue.fetch("netbios_from_scanner"),

          # Or when uses for images & containers in VM
          # "asset_type" => image_or_container,
          # "image_id" => issue.fetch("image_id_from_scanner"),
          # "container_id" => issue.fetch("container_id_from_scanner"),

          # If asset meta data is present
          "owner" => issue.fetch("owner_from_scanner"),
          "tags" => issue.fetch("tags_from_scanner"),
          "os" => issue.fetch("os_from_scanner"),
          "os_version" => issue.fetch("os_version_from_scanner"),
          "priority" => issue.fetch("priority_from_scanner"),

          # An external_id may be used for either VM or Findings model
          "external_id" => issue.fetch("external_id_from_scanner")
        }
        # in case any values are nil, it's good to remove them
        asset.compact
      end

      def extract_finding(issue)
        {
          "scanner_identifier" => issue["serial_number"],
          "scanner_type" => SCANNER_TYPE,
          "vuln_def_name" => issue["issue_type"]["name"],
          "severity" => SEVERITY_VALUE[issue["severity"]],
          "triage_state" => triage_value(issue["confidence"]),
          "additional_fields" => extract_additional_fields(issue)
        }.compact
      end

      # def extract_vuln(issue)
      #   vuln = {
      #     "scanner_type" => SCANNER_TYPE,
      #     "scanner_identifier" => issue.fetch("scanner_id_from_scanner"),
      #     # next is only needed for KDI V2 = vuln short name, text name, or cve or cwe name
      #     "vuln_def_name" => issue.fetch("some_vuln_name"),
      #     "created_at" => issue.fetch("created_from_scanner"),
      #     "scanner_score" => vuln_score,
      #     "last_fixed_on" => issue.fetch("last_fixed_from_scanner"),
      #     "last_seen_at" => issue.fetch("last_seen_from_scanner"),
      #     "status" => issue.fetch("status_from_scanner"),
      #     "closed" => issue.fetch("closed_from_scanner"),
      #     "port" => issue.fetch("port_from_scanner"),
      #     # JSON pretty used for details under vulns only to help with formatting
      #     "details" => JSON.pretty_generate(details_additional_fields)
      #   }
      #   # in case any values are nil, it's good to remove them
      #   issue.compact
      # end

      def extract_definition(issue)
        definition = {
          # PICK (CVE OR CWE OR WASC) OR none but not all three
          # "cve_identifiers" => issue_cve,
          # "wasc_identifiers" => vuln.fetch("wasc_id_from_scanner"),
          "cwe_identifiers" => (issue["issue_type"]["vulnerability_classifications_html"] || "").scan(/CWE-\d*/).join(", "),

          # desc & solution can be left blank for cve and cwe and Kenna will pull in data
          "description" => remove_html_tags(issue["issue_type"]["description_html"] || ""),
          "solution" => remove_html_tags(issue["issue_type"]["remediation_html"] || ""),
          "scanner_type" => SCANNER_TYPE,
          # FOR KDI V2 matches vuln_def_name in vuln / MAY still be present in KDI V1
          "name" => issue["issue_type"]["name"]
        }
        # in case any values are null, it's good to remove them
        definition.compact
      end

      def extract_additional_fields(issue)
        {
          "Sample Severity" => issue["severity"],
          "Confidence" => issue["confidence"],
          "Novelty" => issue["novelty"],
          "Vulnerability Classifications" => remove_html_tags(issue["issue_type"]["vulnerability_classifications_html"] || ""),
          "References" => remove_html_tags(issue["issue_type"]["references_html"] || "")
        }.compact
      end

      def triage_value(triage)
        triage == "false_positive" ? "false_positive" : "new"
      end
    end
  end
end
