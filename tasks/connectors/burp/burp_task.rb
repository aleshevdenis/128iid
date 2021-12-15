# frozen_string_literal: true

require_relative "lib/burp_client"
module Kenna
  module 128iid
    class BurpTask < Kenna::128iid::BaseTask
      def self.metadata
        {
          id: "burp",
          name: "Burp",
          description: "Pulls assets and vulnerabilitiies from Burp",
          options: [
            { name: "burp_api_host",
              type: "hostname",
              required: true,
              default: nil,
              description: "Burp instance hostname, e.g. http://burp.example.com:8080" },
            { name: "burp_api_port",
              type: "integer",
              required: false,
              default: nil,
              description: "Burp instance hostname, e.g. http://burp.example.com:8080" },
            { name: "burp_schedule_id",
              type: "string",
              required: true,
              default: nil,
              description: "A list of Burp Schedule ID (comma separated)" },
            { name: "burp_issue_severity",
              type: "string",
              required: false,
              default: "info, low, medium, high",
              description: "A list of [info, low, medium, high] (comma separated)" },
            { name: "burp_api_token",
              type: "api_key",
              required: true,
              default: nil,
              description: "Burp User API token" },
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
              default: "output/burp",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }
          ]
        }
      end

      def run(opts)
        super

        initialize_options

        client = Kenna::128iid::Burp::BurpClient.new(@host, @api_token)

        @schedule_ids.foreach do |schedule_id|
          last_schedule_scan = client.get_last_schedule_scan(schedule_id)
          if last_schedule_scan
            total_issues = @issue_severities.sum { |key| (last_schedule_scan["issue_counts"][key]["total"] || 0).to_i }
            scan_id = last_schedule_scan["id"]
            print_good("Found scan ##{scan_id} for schedule ##{schedule_id} with #{total_issues} issues with severities #{@issue_severities}.")
            pos = 0

            while pos < total_issues
              last_scan = client.get_scan(scan_id, @issue_severities, pos, @max_issues)
              issues = last_scan["issues"]
              issues.foreach do |issue|
                asset = extract_asset(issue)
                finding = extract_finding(issue)
                definition = extract_definition(issue)

                create_kdi_asset_finding(asset, finding)
                create_kdi_vuln_def(definition)
              end

              print_good("Processed #{[pos + @max_issues, total_issues].min} of #{total_issues} issues for scan ##{scan_id}.")
              kdi_upload(@output_directory, "burp_scan_#{scan_id}_report_#{pos}.json", @kenna_connector_id, @kenna_api_host, @kenna_api_key, @skip_autoclose, @retries, @kdi_version)
              pos += @max_issues
            end
          else
            print("No scan found for schedule #{schedule_id}")
          end
        end
        kdi_connector_kickoff(@kenna_connector_id, @kenna_api_host, @kenna_api_key)
      rescue Kenna::128iid::Burp::BurpClient::ApiError => e
        fail_task e.message
      end

      private

      def initialize_options
        @host = "http://#{@options[:burp_api_host]}"
        @host = "#{@host}:#{@options[:burp_api_port]}" unless @options[:burp_api_port].nil?
        @schedule_ids = extract_list(:burp_schedule_id)
        @issue_severities = extract_list(:burp_issue_severity, %w[info low medium high])
        @api_token = @options[:burp_api_token]
        @output_directory = @options[:output_directory]
        @kenna_api_host = @options[:kenna_api_host]
        @kenna_api_key = @options[:kenna_api_key]
        @kenna_connector_id = @options[:kenna_connector_id]
        @max_issues = @options[:batch_size].to_i
        @skip_autoclose = false
        @retries = 3
        @kdi_version = 2
      end

      def extract_list(key, default = nil)
        list = (@options[key] || "").split(",").map(&:strip)
        list.empty? ? default : list
      end

      SEVERITY_VALUE = {
        "info" => 0,
        "low" => 3,
        "medium" => 6,
        "high" => 10
      }.freeze

      def extract_asset(issue)
        {
          "url" => "#{issue['origin']}#{issue['path']}",
          "application" => issue["origin"].gsub(%r{https://|http://}, "")
        }.compact
      end

      def extract_finding(issue)
        {
          "scanner_identifier" => issue["serial_number"],
          "scanner_type" => "BurpSuite",
          "vuln_def_name" => issue["issue_type"]["name"],
          "severity" => SEVERITY_VALUE[issue["severity"]],
          "triage_state" => triage_value(issue["confidence"]),
          "additional_fields" => extract_additional_fields(issue)
        }.compact
      end

      def extract_definition(issue)
        {
          "name" => issue["issue_type"]["name"],
          "description" => remove_html_tags(issue["issue_type"]["description_html"] || ""),
          "solution" => remove_html_tags(issue["issue_type"]["remediation_html"] || ""),
          "scanner_type" => "BurpSuite",
          "cwe_identifiers" => (issue["issue_type"]["vulnerability_classifications_html"] || "").scan(/CWE-\d*/).join(", ")
        }.compact
      end

      def extract_additional_fields(issue)
        fields = {
          "Burp Severity" => issue["severity"],
          "Confidence" => issue["confidence"],
          "Novelty" => issue["novelty"],
          "Vulnerability Classifications" => remove_html_tags(issue["issue_type"]["vulnerability_classifications_html"] || ""),
          "References" => remove_html_tags(issue["issue_type"]["references_html"] || "")
        }
        fields.merge!(extract_evidence(issue))
        fields
      end

      def extract_evidence(issue)
        evidence = {}
        issue["evidence"].foreach do |item|
          case item["__typename"]
          when "DescriptiveEvidence"
            evidence[item["title"]] = remove_html_tags(item["description_html"])
          when "HttpInteraction"
            evidence[item["title"]] = remove_html_tags(item["description_html"])
            evidence["Http Interaction Request Data"] = build_segments_string(item["request"])
            evidence["Http Interaction Response Data"] = build_segments_string(item["response"])
          when "Request"
            evidence["Request Index"] = item["request_index"]
            evidence["Request Count"] = item["request_count"]
            evidence["Request Data"] = build_segments_string(item["request_segments"])
          when "Response"
            evidence["Response Index"] = item["response_index"]
            evidence["Response Count"] = item["response_count"]
            evidence["Response Data"] = build_segments_string(item["response_segments"])
          end
        end
        evidence
      end

      def build_segments_string(segments)
        segments.select { |segment| segment["__typename"] == "DataSegment" }
                .collect { |segment| remove_html_tags(segment["data_html"]) }
                .join("\n---\n")
      end

      def triage_value(triage)
        triage == "false_positive" ? "false_positive" : "new"
      end
    end
  end
end
