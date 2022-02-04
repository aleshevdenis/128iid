# frozen_string_literal: true

require_relative "lib/hackerone_client"

module Kenna
  module 128iid
    class HackeroneTask < Kenna::128iid::BaseTask
      SCANNER_TYPE = "Hackerone"
      def self.metadata
        {
          id: "hackerone",
          name: "Hackerone",
          description: "Pulls assets and vulnerabilities from Hackerone",
          options: [
            { name: "hackerone_api_user",
              type: "api_key",
              required: true,
              default: nil,
              description: "HackerOne API User" },
            { name: "hackerone_api_password",
              type: "api_key",
              required: true,
              default: nil,
              description: "HackerOne API Password" },
            { name: "hackerone_program_name",
              type: "string",
              required: true,
              default: nil,
              description: "HackerOne API Program Name" },
            { name: "hackerone_issue_severity",
              type: "string",
              required: false,
              default: nil,
              description: "A list of [none low medium high critical] (comma separated). Only issues with one of these severities are imported. If not present, ALL will be imported." },
            { name: "page_size",
              type: "integer",
              required: false,
              default: 100,
              description: "The number of objects per page (currently limited from 1 to 100)." },
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
              default: "output/hackerone",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }
          ]
        }
      end

      def run(opts)
        super

        initialize_options
        initialize_client

        offset = 1

        loop do
          response = client.get_reports(offset, @page_size, submissions_filter)
          break unless response["data"].any?

          response["data"].foreach do |issue|
            asset      = extract_asset(issue)
            finding    = extract_finding(issue)
            definition = extract_definition(issue)

            create_kdi_asset_finding(asset, finding)
            create_kdi_vuln_def(definition)
          end

          print_good("Processed #{offset} submissions.")

          kdi_upload(@output_directory, "hackerone_submissions_report_#{offset}.json", @kenna_connector_id, @kenna_api_host, @kenna_api_key, @skip_autoclose, @retries, @kdi_version)
          offset += 1
        end

        kdi_connector_kickoff(@kenna_connector_id, @kenna_api_host, @kenna_api_key)
      rescue Kenna::128iid::Hackerone::HackeroneClient::ApiError => e
        fail_task e.message
      end

      private

      attr_reader :client

      def initialize_client
        @client = Kenna::128iid::Hackerone::HackeroneClient.new(@api_user, @api_password, @program_name)
      end

      def initialize_options
        @api_user           = @options[:hackerone_api_user]
        @api_password       = @options[:hackerone_api_password]
        @program_name       = @options[:hackerone_program_name]
        @output_directory   = @options[:output_directory]
        @issue_severities   = extract_list(:hackerone_issue_severity, %w[none low medium high critical])
        @kenna_api_host     = @options[:kenna_api_host]
        @kenna_api_key      = @options[:kenna_api_key]
        @kenna_connector_id = @options[:kenna_connector_id]
        @page_size          = @options[:page_size].to_i
        @skip_autoclose     = false
        @retries            = 3
        @kdi_version        = 2
        fail_task "The number of objects per page (currently limited from 1 to 100)." unless @page_size.between?(1, 100)
      end

      def extract_asset(issue)
        asset = {}

        asset_type          = issue.dig("relationships", "structured_scope", "data", "attributes", "asset_type")
        asset_identifier    = issue.dig("relationships", "structured_scope", "data", "attributes", "asset_identifier")
        asset[:application] = issue.dig("relationships", "program", "data", "attributes", "handle")

        case asset_type
        when "SOURCE_CODE", "URL"
          asset[:url]         = asset_identifier
        when "DOWNLOADABLE_EXECUTABLES"
          asset[:file]        = asset_identifier
        when ""
          asset[:file]        = "hacker_one_missing_asset"
        else
          asset[:external_id] = "#{asset_type}-#{asset_identifier}"
        end

        asset.compact
      end

      def extract_finding(issue)
        {
          "scanner_type" => "HackerOne",
          "scanner_identifier" => issue["id"],
          "vuln_def_name" => issue.dig("relationships", "weakness", "data", "attributes", "name"),
          "severity" => SEVERITY_VALUE[issue.dig("relationships", "severity", "data", "attributes", "rating")],
          "triage_state" => map_state_to_triage_state(issue.dig("attributes", "state")),
          "created_at" => convert_date(issue.dig("attributes", "created_at")),
          "additional_fields" => extract_additional_fields(issue)
        }.compact
      end

      def extract_additional_fields(issue)
        fields = {}
        fields["Severity"]            = issue.dig("relationships", "severity", "data", "attributes")
        fields["Structured Scope"]    = issue.dig("relationships", "structured_scope", "data", "attributes")
        fields["Custom Field Values"] = issue.dig("relationships", "custom_field_values", "data")
        fields.merge(issue["attributes"].compact)
      end

      def extract_definition(issue)
        {
          "scanner_type" => "HackerOne",
          "cwe_identifiers" => (issue["relationships"]["weakness"]["data"]["attributes"]["external_id"] || "").upcase.scan(/CWE-\d*/).join(", "),
          "name" => issue.dig("relationships", "weakness", "data", "attributes", "name"),
          "description" => issue.dig("relationships", "weakness", "data", "attributes", "description")
        }.compact
      end

      def submissions_filter
        {
          "severity" => extract_list(:severity),
          "state" => check_state(@options[:state])
        }.compact
      end

      def check_state(state)
        if state == "not-resolved"
          NOT_RESOLVED
        else
          extract_list(:state)
        end
      end

      def convert_date(date_string)
        Time.parse(date_string).to_datetime.iso8601
      rescue StandardError
        nil
      end

      def extract_list(key, default = nil)
        list = (@options[key] || "").split(",").map(&:strip)
        list.empty? ? default : list
      end

      NOT_RESOLVED = %w[new pending-program-review triaged needs-more-info not-applicable
                        informative duplicate spam retesting].freeze

      SEVERITY_VALUE = {
        "none" => 0,
        "low" => 3,
        "medium" => 5,
        "high" => 8,
        "critical" => 10
      }.freeze

      def map_state_to_triage_state(hackerone_state)
        case hackerone_state
        when "new", "triaged", "resolved"
          hackerone_state
        when "pending-program-review", "needs-more-info", "retesting"
          "in_progress"
        else
          "not_a_security_issue"
        end
      end
    end
  end
end
