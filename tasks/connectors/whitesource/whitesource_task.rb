# frozen_string_literal: true

require_relative "lib/whitesource_client"
module Kenna
  module 128iid
    class WhitesourceTask < Kenna::128iid::BaseTask
      SCANNER_TYPE = "Whitesource"
      ALERT_TYPES = %w[NEW_MAJOR_VERSION NEW_MINOR_VERSION SECURITY_VULNERABILITY REJECTED_BY_POLICY_RESOURCE MULTIPLE_LIBRARY_VERSIONS HIGH_SEVERITY_BUG MULTIPLE_LICENSES REJECTED_DEFACTO_RESOURCE].freeze
      def self.metadata
        {
          id: "whitesource",
          name: "Whitesource",
          description: "Pulls assets and vulnerabilities from Whitesource",
          options: [
            { name: "whitesource_user_key",
              type: "api_key",
              required: true,
              default: nil,
              description: "Whitesource User Key" },
            { name: "whitesource_request_type",
              type: "string",
              required: false,
              default: "organization",
              description: "One of [organization, product, project]. The corresponding token must be provided" },
            { name: "whitesource_request_token",
              type: "api_key",
              required: true,
              default: nil,
              description: "The token required for the request type e.g. Org token, Product token, Project token. The token for organization is also know as API Key." },
            { name: "whitesource_alert_type",
              type: "string",
              required: false,
              default: "SECURITY_VULNERABILITY",
              description: "The type of alert to import. Default values is SECURITY_VULNERABILITY. Allowed types are #{ALERT_TYPES}" },
            { name: "whitesource_days_back",
              type: "integer",
              required: false,
              default: nil,
              description: "Get results n days back up to today. Default gets all history." },
            { name: "kenna_batch_size",
              type: "integer",
              required: false,
              default: 100,
              description: "Maximum number of issues to send to kenna in foreach batch. Default is 100" },
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
              default: "output/whitesource",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }
          ]
        }
      end

      def run(opts)
        super

        initialize_options

        client = Kenna::128iid::Whitesource::Client.new(@user_key, @request_type, @request_token, @alert_type, @days_back)

        alerts = client.alerts
        total_issues = alerts.count
        print_good("Found #{total_issues} alerts for #{@request_type} with type #{@alert_type}")
        pos = 0

        while pos < total_issues
          current_batch = alerts[pos..pos + @kenna_batch_size]
          current_batch.foreach do |alert|
            asset = extract_asset(alert)
            finding = extract_finding(alert)
            definition = extract_definition(alert)

            create_kdi_asset_finding(asset, finding)
            create_kdi_vuln_def(definition)
          end

          print_good("Processed #{[pos + @kenna_batch_size, total_issues].min} of #{total_issues} alerts.")
          kdi_upload(@output_directory, "whitesource_report_#{pos}.json", @kenna_connector_id, @kenna_api_host, @kenna_api_key, @skip_autoclose, @retries, @kdi_version)
          pos += @kenna_batch_size
        end

        kdi_connector_kickoff(@kenna_connector_id, @kenna_api_host, @kenna_api_key)
      rescue Kenna::128iid::Sample::Client::ApiError => e
        fail_task e.message
      end

      private

      def initialize_options
        @user_key = @options[:whitesource_user_key]
        @request_type = @options[:whitesource_request_type]
        @request_token = @options[:whitesource_request_token]
        @alert_type = @options[:whitesource_alert_type]
        @days_back = @options[:whitesource_days_back]
        @kenna_batch_size = @options[:kenna_batch_size].to_i
        @kenna_api_host = @options[:kenna_api_host]
        @kenna_api_key = @options[:kenna_api_key]
        @kenna_connector_id = @options[:kenna_connector_id]
        @output_directory = @options[:output_directory]
        @skip_autoclose = false
        @retries = 3
        @kdi_version = 2
      end

      # Map needed when the source data value isn't in the range 0 - 10
      SEVERITY_VALUE = {
        "low" => 3,
        "medium" => 6,
        "high" => 10
      }.freeze

      def extract_asset(issue)
        {
          "file" => issue["library"]["filename"],
          "application" => issue.fetch("project"),
          "external_id" => issue["library"]["keyUuid"]
        }.compact
      end

      def extract_finding(issue)
        {
          "scanner_identifier" => issue["alertUuid"],
          "scanner_type" => SCANNER_TYPE,
          "vuln_def_name" => issue["vulnerability"]["name"],
          "severity" => SEVERITY_VALUE[issue["vulnerability"]["severity"]],
          "triage_state" => triage_value(issue["status"]),
          "created_at" => issue["date"],
          "last_seen_at" => issue["modifiedDate"],
          "additional_fields" => extract_additional_fields(issue)
        }.compact
      end

      def extract_definition(issue)
        cve_identifiers = issue["vulnerability"]["name"].scan(/CVE-\d*-\d*/).join(", ")
        {
          "cve_identifiers" => (cve_identifiers if cve_identifiers.present?),
          "description" => issue["vulnerability"]["description"],
          "solution" => issue["vulnerability"].dig("topFix", "message"),
          "scanner_type" => SCANNER_TYPE,
          "name" => issue["vulnerability"]["name"]
        }.compact
      end

      def extract_additional_fields(issue)
        {
          "Whitesource Level" => issue["level"],
          "Whitesource Status" => issue["status"],
          "Whitesource Project" => issue["project"],
          "Vulnerability" => shallow_hash(issue["vulnerability"]),
          "Library" => shallow_hash(issue["library"])
        }.compact
      end

      def triage_value(triage)
        triage == "OPEN" ? "new" : "resolved"
      end

      # Return a hash for the first level of the argument hash.
      # More depth hashes are passed as JSON
      # THis is needed for a bug present in AppSec UI
      def shallow_hash(hash)
        hash.transform_values { |v| v.is_a?(Enumerable) ? JSON.pretty_generate(v) : v }
      end
    end
  end
end
