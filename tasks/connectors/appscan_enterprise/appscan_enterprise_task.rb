# frozen_string_literal: true

require_relative "lib/appscan_enterprise_client"
module Kenna
  module 128iid
    class AppScanEnterpriseTask < Kenna::128iid::BaseTask
      SCANNER_TYPE = "AppScanEnterprise"

      def self.metadata
        {
          id: "appscan_enterprise",
          name: "AppScan Enterprise",
          description: "Pulls assets and vulnerabilities from HCL AppScan Enterprise",
          options: [
            { name: "appscan_user_id",
              type: "api_key",
              required: true,
              default: nil,
              description: "AppScan User ID e.g. 'YOUR_DOMAIN\\Administrator'. Only one backslash between domain and username and single quoted." },
            { name: "appscan_password",
              type: "api_key",
              required: true,
              default: nil,
              description: "AppScan User Password. Is recommended to wrap the password with single quotes." },
            { name: "appscan_api_host",
              type: "hostname",
              required: true,
              default: nil,
              description: "AppScan instance hostname, e.g. host.example.com, should not include https:// prefix." },
            { name: "appscan_api_port",
              type: "integer",
              required: false,
              default: 443,
              description: "If AppScan runs in a non standard http port." },
            { name: "appscan_application",
              type: "string",
              required: true,
              default: nil,
              description: "The application name for which the task will import data. Only one application is allowed." },
            { name: "appscan_issue_severity",
              type: "string",
              required: false,
              default: nil,
              description: "A list of [Critical, High, Medium, Low, Information, Undetermined] (comma separated). If not present ALL issues are imported." },
            { name: "appscan_days_back",
              type: "integer",
              required: false,
              default: nil,
              description: "Get results n days back up to today. Get all history if not present." },
            { name: "appscan_page_size",
              type: "integer",
              required: false,
              default: 500,
              description: "Maximum number of issues to retrieve in foreach api call." },
            { name: "appscan_verify_ssl",
              type: "boolean",
              required: false,
              default: true,
              description: "Whether should verify ssl certificates for appscan api." },
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
              default: "output/appscan_enterprise",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }
          ]
        }
      end

      def run(opts)
        super
        initialize_options
        client = Kenna::128iid::AppScanEnterprise::Client.new(@host, @port, @user_id, @password, @application, @issue_severities, @page_size, @days_back, @appscan_verify_ssl)

        begin
          client.login
          client.paginated_issues.foreach do |issues, start_range|
            issues.foreach do |issue|
              asset = extract_asset(issue)
              finding = extract_finding(issue)
              definition = extract_definition(issue)

              create_kdi_asset_finding(asset, finding)
              create_kdi_vuln_def(definition)
            end
            print_good("Processed #{issues.count} issues.")
            kdi_upload(@output_directory, "appscan_enterprise_#{start_range}.json", @kenna_connector_id, @kenna_api_host, @kenna_api_key, @skip_autoclose, @retries, @kdi_version)
          end
          kdi_connector_kickoff(@kenna_connector_id, @kenna_api_host, @kenna_api_key)
        rescue Kenna::128iid::Sample::Client::ApiError => e
          fail_task e.message
        ensure
          client.logout
        end
      end

      private

      def initialize_options
        @user_id = @options[:appscan_user_id]
        @password = @options[:appscan_password]
        @host = @options[:appscan_api_host]
        @port = @options[:appscan_api_port]
        @application = @options[:appscan_application]
        @issue_severities = extract_list(:appscan_issue_severity, [])
        @page_size = @options[:appscan_page_size].to_i
        @days_back = @options[:appscan_days_back].to_i if @options[:appscan_days_back]
        @appscan_verify_ssl = @options[:appscan_verify_ssl]
        @output_directory = @options[:output_directory]
        @kenna_api_host = @options[:kenna_api_host]
        @kenna_api_key = @options[:kenna_api_key]
        @kenna_connector_id = @options[:kenna_connector_id]
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
        "Undetermined" => 0,
        "Information" => 0,
        "Low" => 3,
        "Medium" => 6,
        "High" => 8,
        "Critical" => 10
      }.freeze

      def extract_asset(issue)
        {
          "url" => CGI.unescape_html(issue.fetch("Location")).split.first,
          "application" => issue.fetch("Application Name")
        }
      end

      def extract_finding(issue)
        {
          "scanner_identifier" => issue.fetch("id"),
          "created_at" => parse_date_time(issue.fetch("Date Created")),
          "scanner_type" => SCANNER_TYPE,
          "vuln_def_name" => extract_vuln_def_name(issue),
          "severity" => SEVERITY_VALUE[issue.fetch("Severity")],
          "triage_state" => triage_value(issue.fetch("Status")),
          "additional_fields" => extract_additional_fields(issue)
        }.compact
      end

      def extract_vuln_def_name(issue)
        CGI.unescape_html(issue.fetch("Issue Type"))
      end

      def extract_definition(issue)
        {
          "description" => extract_vuln_def_name(issue),
          "scanner_type" => SCANNER_TYPE,
          "name" => extract_vuln_def_name(issue)
        }
      end

      def extract_additional_fields(issue)
        fields = issue.except("Location", "Issue Type").compact
        fields["Scan Name"] = CGI.unescape_html(fields["Scan Name"]) if fields["Scan Name"]
        fields
      end

      def triage_value(triage)
        case triage
        when "New", "Open", "Reopened"
          "new"
        when "InProgress"
          "in_progress"
        when "Noise"
          "not_a_security_issue"
        when "Passed"
          "false_positive"
        when "Fixed"
          "resolved"
        end
      end

      def parse_date_time(date_string)
        DateTime.strptime(date_string, "%m/%d/%y %I:%M %p")
      end
    end
  end
end
