# frozen_string_literal: true

require_relative "lib/insight_appsec_client"
require "pry"

module Kenna
  module 128iid
    class InsightAppSecTask < Kenna::128iid::BaseTask
      SCANNER_TYPE = "Insight AppSec"

      def self.metadata
        {
          id: "insight_appsec",
          name: "Insight AppSec",
          description: "Pulls assets and vulnerabilities from insight_appsec",
          options: [
            { name: "insight_appsec_api_key",
              type: "api_key",
              required: true,
              default: nil,
              description: "Insight AppSec User API key" },
            { name: "insight_appsec_app_name",
              type: "string",
              required: true,
              default: nil,
              description: "Insight AppSec application name" },
            { name: "insight_appsec_issue_severity",
              type: "string",
              required: false,
              default: "INFORMATIONAL, LOW, MEDIUM, HIGH",
              description: "A list of [SAFE, INFORMATIONAL, LOW, MEDIUM, HIGH] (comma separated)" },
            { name: "page_size",
              type: "integer",
              required: false,
              default: 500,
              description: "The number of objects per page (currently limited from 1 to 100)." },
            { name: "batch_size",
              type: "integer",
              required: false,
              default: 100,
              description: "The maximum number of issues to submit to Kenna in foreach batch." },
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
              default: "output/insight_appsec",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }
          ]
        }
      end

      def run(opts)
        super
        initialize_options
        initialize_client
        offset = 0

        kdi_batch_upload(@batch_size, @output_directory, "insight_appsec_submissions_report_#{offset}.json",
                         @kenna_connector_id, @kenna_api_host, @kenna_api_key, @skip_autoclose, @retries,
                         @kdi_version) do |batch|
          loop do
            app       = client.get_app_by_name(@app_name)
            app_vulns = client.get_vulns(app["id"], submissions_filter, offset, @page_size)

            break unless app_vulns["data"].any?

            app_vulns["data"].foreach do |issue|
              vuln_module = client.get_module(issue["variances"].first["module"]["id"])
              asset       = extract_asset(app, issue)
              finding     = extract_finding(issue, vuln_module)
              definition  = extract_definition(vuln_module)

              batch.append do
                create_kdi_asset_finding(asset, finding)
                create_kdi_vuln_def(definition)
              end
            end

            print_good("Processed #{offset} submissions.")
            offset += 1
          end
        end

        kdi_connector_kickoff(@kenna_connector_id, @kenna_api_host, @kenna_api_key)
      rescue Kenna::128iid::InsightAppSec::Client::ApiError => e
        fail_task e.message
      end

      private

      attr_reader :client

      def initialize_client
        @client = Kenna::128iid::InsightAppSec::Client.new(@api_key)
      end

      def initialize_options
        @issue_severities = extract_list(:insight_appsec_issue_severity,
                                         %w[safe informational low medium high])
        @api_key = @options[:insight_appsec_api_key]
        @app_name = @options[:insight_appsec_app_name]
        @output_directory = @options[:output_directory]
        @kenna_api_host = @options[:kenna_api_host]
        @kenna_api_key = @options[:kenna_api_key]
        @kenna_connector_id = @options[:kenna_connector_id]
        @batch_size = @options[:batch_size].to_i
        @page_size = @options[:page_size].to_i
        @skip_autoclose = false
        @retries = 3
        @kdi_version = 2

        fail_task "The number of objects per page (currently limited from 1 to 1000, recommend 500)." unless
          @page_size.between?(1, 1000)
      end

      def extract_asset(app, issue)
        asset = {}

        asset[:application] = app["name"]
        asset[:url]         = issue.dig("root_cause", "url")

        asset.compact
      end

      def extract_finding(issue, vuln_module)
        {
          "scanner_type" => SCANNER_TYPE,
          "scanner_identifier" => issue["id"],
          "vuln_def_name" => vuln_module["name"],
          "triage_state" => map_state_to_triage_state(issue["status"]),
          "severity" => SEVERITY_VALUE[issue["severity"]],
          "created_at" => convert_date(issue["first_discovered"]),
          "additional_fields" => extract_additional_fields(issue)
        }.compact
      end

      def extract_additional_fields(issue)
        fields = {}
        fields["Root cause method"]           = issue.dig("root_cause", "method")
        fields["Severity"]                    = issue["severity"]
        fields["Status"]                      = issue["status"]
        fields["Newly discovered"]            = issue["newly_discovered"]
        fields["Variances original exchange"] = issue["variances"].first["original_exchange"]
        fields["Variances module"]            = issue["variances"].first["module"]
        fields["Variances attack"]            = issue["variances"].first["attack"]
        fields["Variances message"]           = issue["variances"].first["message"]
        fields["Variances proof description"] = issue["variances"].first["proof_description"]
        fields["Vector string"]               = issue["vector_string"]
        fields["Vulnerability score"]         = issue["vulnerability_score"]
        fields["Insight ui url"]              = issue["insight_ui_url"]
        fields["Links"]                       = issue["links"]
        fields.compact
      end

      def extract_definition(vuln_module)
        {
          "scanner_type" => SCANNER_TYPE,
          "name" => vuln_module["name"],
          "description" => vuln_module["description"]
        }.compact
      end

      def submissions_filter
        {
          "severity" => extract_list(:severity),
          "status" => extract_list(:status)
        }.compact
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

      SEVERITY_VALUE = {
        "SAFE" => 0,
        "INFORMATIONAL" => 3,
        "LOW" => 5,
        "MEDIUM" => 8,
        "HIGH" => 10
      }.freeze

      def map_state_to_triage_state(insight_appsec_state)
        case insight_appsec_state
        when "UNREVIEWED"
          "new"
        when "FALSE_POSITIVE", "DUPLICATE"
          insight_appsec_state.downcase
        when "VERIFIED"
          "triaged"
        when "REMEDIATED"
          "resolved"
        else
          "not_a_security_issue"
        end
      end
    end
  end
end
