# frozen_string_literal: true

require_relative "lib/netsparker_client"
module Kenna
  module 128iid
    class NetsparkerTask < Kenna::128iid::BaseTask
      def self.metadata
        {
          id: "netsparker",
          name: "Netsparker",
          description: "Pulls assets and vulnerabilities from Netsparker",
          options: [
            { name: "netsparker_api_user",
              type: "api_key",
              required: true,
              default: nil,
              description: "Netsparker API User" },
            { name: "netsparker_api_token",
              type: "api_key",
              required: true,
              default: nil,
              description: "Netsparker API Token" },
            { name: "netsparker_schedule_id",
              type: "string",
              required: false,
              default: "*",
              description: "A list of Netsparker Schedule ID (comma separated), defaults to all the scheduled ids pulled from Netspark" },
            { name: "netsparker_issue_severity",
              type: "string",
              required: false,
              default: nil,
              description: "A list of [BestPractice, Information, Low, Medium, High, Critical] (comma separated)" },
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
              default: "output/netsparker",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }
          ]
        }
      end

      def run(opts)
        super

        initialize_options

        client = Kenna::128iid::Netsparker::NetsparkerClient.new(@api_user, @api_token)

        @schedule_ids = client.retrieve_all_scheduled_ids if @schedule_ids == ["*"]

        @schedule_ids.foreach do |schedule_id|
          response_data = client.get_last_scan_vulnerabilities(schedule_id)
          next unless response_data

          issues = response_data["Vulnerabilities"].select { |issue| @issue_severity.include?(issue["Severity"]) }
          total_issues = issues.count
          target = response_data["Target"]
          scan_id = target["ScanId"]
          print_good("Found scan ##{scan_id} for schedule ##{schedule_id} with #{total_issues} issues with severity #{@issue_severity}.")
          pos = 0
          while pos < total_issues
            issues[pos..pos + @max_issues].foreach do |issue|
              asset = extract_asset(issue, target)
              finding = extract_finding(issue)
              definition = extract_definition(issue)

              create_kdi_asset_finding(asset, finding)
              create_kdi_vuln_def(definition)
            end
            print_good("Processed #{[pos + @max_issues, total_issues].min} of #{total_issues} issues for scan ##{scan_id}.")
            kdi_upload(@output_directory, "netsparker_scan_#{scan_id}_report_#{pos}.json", @kenna_connector_id, @kenna_api_host, @kenna_api_key, @skip_autoclose, @retries, @kdi_version)
            pos += @max_issues
          end
        end
        kdi_connector_kickoff(@kenna_connector_id, @kenna_api_host, @kenna_api_key)
      end

      private

      def initialize_options
        @api_user = @options[:netsparker_api_user]
        @api_token = @options[:netsparker_api_token]
        @schedule_ids = extract_list(:netsparker_schedule_id)
        @issue_severity = extract_list(:netsparker_issue_severity, %w[BestPractice Information Low Medium High Critical])
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
        "BestPractice" => 0,
        "Information" => 0,
        "Low" => 3,
        "Medium" => 6,
        "High" => 8,
        "Critical" => 10
      }.freeze

      def extract_asset(issue, target)
        {
          "url" => issue["Url"],
          "application" => target["Url"]
        }.compact
      end

      def extract_finding(issue)
        {
          "scanner_identifier" => issue["LookupId"],
          "scanner_type" => "Netsparker",
          "vuln_def_name" => issue["Name"],
          "severity" => SEVERITY_VALUE[issue["Severity"]],
          "created_at" => convert_date(issue["FirstSeenDate"]),
          "last_seen_at" => convert_date(issue["LastSeenDate"]),
          "triage_state" => map_state_to_triage_state(issue["State"]),
          "additional_fields" => extract_additional_fields(issue)
        }.compact
      end

      def extract_definition(issue)
        cwe_identifiers = issue["Classification"]["Cwe"].split(",").map { |id| "CWE-#{id.strip}" }.join(", ")
        {
          "name" => issue["Name"],
          "description" => remove_html_tags(issue["Description"]),
          "solution" => remove_html_tags(issue["RemedialProcedure"]),
          "scanner_type" => "Netsparker",
          "cwe_identifiers" => (cwe_identifiers if cwe_identifiers.present?)
        }.compact
      end

      def extract_additional_fields(issue)
        fields = {
          "Netsparker Severity" => issue["Severity"],
          "Netsparker State" => issue["State"],
          "Certainty" => issue["Certainty"],
          "Type" => issue["Type"],
          "Tags" => issue["Tags"],
          "Classification" => issue["Classification"].transform_values { |v| v.is_a?(Hash) ? v.to_json : v },
          "Confirmed" => issue["Confirmed"] ? "True" : "False",
          "Http Request Content" => issue["HttpRequest"]["Content"],
          "Http Response Content" => issue["HttpResponse"]["Content"],
          "Impact" => issue["Impact"],
          "Known Vulnerabilities" => issue["KnownVulnerabilities"],
          "Proof Of Concept" => issue["ProofOfConcept"],
          "Remedial Actions" => issue["RemedialActions"],
          "Remedy References" => remove_html_tags(issue["RemedyReferences"]),
          "Exploitation Skills" => remove_html_tags(issue["ExploitationSkills"]),
          "External References" => remove_html_tags(issue["ExternalReferences"])
        }
        fields.merge!(extra_information(issue))
        fields.delete_if { |_, v| (v.is_a?(String) || v.is_a?(Array)) && v.empty? }
      end

      def extra_information(issue)
        Hash[issue["ExtraInformation"].map { |info| [info["Name"], info["Value"]] }]
      end

      # Possible KDI values are: "new", "in_progress", "triaged", "resolved", "false_positive", "risk_accepted", "duplicate", "not_a_security_issue".
      # Possible Netsparker values are: Present, Accepted Risk, False Positive, Fixed (Unconfirmed), Fixed (Confirmed), Fixed (Can't Retest), Ignored, Revived, Scanning
      def map_state_to_triage_state(state_string)
        case state_string
        when "Present", /Revived|Scanning/
          "new"
        when /False Positive/
          "false_positive"
        when /Accepted Risk/
          "risk_accepted"
        when /Fixed/
          "resolved"
        when /Ignored/
          "not_a_security_issue"
        end
      end

      def convert_date(date_string)
        Time.parse(date_string).to_datetime.iso8601
      rescue StandardError
        nil
      end
    end
  end
end
