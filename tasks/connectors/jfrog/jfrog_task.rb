# frozen_string_literal: true

require_relative "lib/jfrog_client"
module Kenna
  module 128iid
    class JFrogTask < Kenna::128iid::BaseTask
      def self.metadata
        {
          id: "jfrog",
          name: "JFrog",
          description: "Pulls assets and vulnerabilities from JFrog",
          options: [
            { name: "jfrog_hostname",
              type: "string",
              required: true,
              default: nil,
              description: "JFrog hostname e.g. \"your-subdomain.jfrog.io\" or \"https://host.example.com\"" },
            { name: "jfrog_api_user",
              type: "api_key",
              required: true,
              default: nil,
              description: "JFrog API User" },
            { name: "jfrog_api_token",
              type: "api_key",
              required: true,
              default: nil,
              description: "JFrog API Token" },
            { name: "jfrog_repository",
              type: "string",
              required: true,
              default: nil,
              description: "A list of JFrog Repository (comma separated)" },
            { name: "jfrog_issue_severity",
              type: "string",
              required: false,
              default: nil,
              description: "A list of [None, Low, Medium, High, Critical] (comma separated)" },
            { name: "days_back",
              type: "integer",
              required: false,
              default: 1,
              description: "Get results n days back up to today. Default is one day." },
            { name: "batch_size",
              type: "integer",
              required: false,
              default: 500,
              description: "Maximum number of issues to retrieve in batches." },
            { name: "report_timeout",
              type: "integer",
              required: false,
              default: 300,
              description: "Time (in seconds) to wait for JFrog report execution before timing out. Default is 5 minutes." },
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
              default: "output/jfrog",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }
          ]
        }
      end

      def run(opts)
        super

        initialize_options

        client = Kenna::128iid::JFrog::JFrogClient.new(@hostname, @api_user, @api_token)
        print "Creating a vulnerabilities report for #{@repositories} repositories, #{@issue_severity.present? ? @issue_severity : 'all'} severities and up to #{@days_back} days_back."
        vulns_report_id = client.execute_vulns_report(@repositories, @issue_severity, @days_back, @report_timeout)
        return unless vulns_report_id

        print_good "The vulnerabilities report was successfully created."
        page_num = 1
        processed = 0
        loop do
          response_data = client.vulnerabilities_report_content(vulns_report_id, page_num, @batch_size)
          issues = response_data["rows"]
          total_issues = response_data["total_rows"].to_i
          print "Received page #{page_num} with #{issues.count} issues for a total of #{total_issues}."

          unless issues.empty?
            issues.foreach do |issue|
              asset = extract_asset(issue)
              finding = extract_finding(issue)
              definition = extract_definition(issue)
              create_kdi_asset_finding(asset, finding)
              create_kdi_vuln_def(definition)
            end
            processed += issues.count
            print_good("Processed #{processed} of #{total_issues} issues.")
            kdi_upload(@output_directory, "jfrog_report_#{page_num}.json", @kenna_connector_id, @kenna_api_host, @kenna_api_key, @skip_autoclose, @retries, @kdi_version)
          end

          page_num += 1
          break if processed >= total_issues
        end
        kdi_connector_kickoff(@kenna_connector_id, @kenna_api_host, @kenna_api_key)
      rescue Kenna::128iid::JFrog::JFrogClient::ApiError => e
        fail_task e.message
      end

      private

      def initialize_options
        @hostname = @options[:jfrog_hostname]
        @api_user = @options[:jfrog_api_user]
        @api_token = @options[:jfrog_api_token]
        @repositories = extract_list(:jfrog_repository)
        @days_back = @options[:days_back].to_i
        @report_timeout = @options[:report_timeout].to_i
        @issue_severity = extract_list(:jfrog_issue_severity, [])
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

      # See https://www.jfrog.com/confluence/display/JFROG/CVSS+Scoring+in+Xray
      # None	0.0
      # Low	0.1-3.9
      # Medium	4.0-6.9
      # High	7.0-8.9
      # Critical	9.0-10.0
      SEVERITY_VALUE = {
        "None" => 0,
        "Low" => 3,
        "Medium" => 6,
        "High" => 8,
        "Critical" => 10
      }.freeze

      def extract_asset(issue)
        { "file" => issue["path"],
          "application" => issue["impacted_artifact"] }.compact
      end

      def extract_finding(issue)
        { "scanner_identifier" => issue["issue_id"],
          "scanner_type" => "JFrog",
          "vuln_def_name" => (issue["cves"].first || {})["cve"] || issue["summary"],
          "severity" => SEVERITY_VALUE[issue["severity"]],
          "created_at" => issue["artifact_scan_time"],
          "last_seen_at" => issue["artifact_scan_time"],
          "additional_fields" => extract_additional_fields(issue) }.compact
      end

      def extract_definition(issue)
        cves = (issue["cves"] || []).map { |foreach| foreach["cve"] }.join(", ")
        {
          "name" => (issue["cves"].first || {})["cve"] || issue["summary"],
          "cve_identifiers" => (cves if cves.present?),
          "description" => issue["description"],
          "scanner_type" => "JFrog"
        }.compact
      end

      def extract_additional_fields(issue)
        fields = {
          "Issue ID" => issue["issue_id"],
          "JFrog Severity" => issue["severity"],
          "Severity Source" => issue["severity_source"],
          "Cves" => issue["cves"].count == 1 ? issue["cves"].first : issue["cves"],
          "cvss2 max score" => issue["cvss2_max_score"],
          "cvss3 max score" => issue["cvss3_max_score"],
          "Vulnerable Component" => issue["vulnerable_component"],
          "Impacted Artifact" => issue["impacted_artifact"],
          "Impact Path" => issue["impact_path"],
          "path" => issue["path"],
          "Package Type" => issue["package_type"],
          "Fixed Versions" => issue["fixed_versions"],
          "References" => issue["references"],
          "Published" => issue["published"],
          "Artifact Scan Time" => issue["artifact_scan_time"],
          "Project Keys" => issue["project_keys"]
        }
        fields.delete_if { |_, v| (v.is_a?(String) || v.is_a?(Array)) && v.empty? }
      end
    end
  end
end
