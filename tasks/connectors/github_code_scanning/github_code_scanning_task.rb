# frozen_string_literal: true

require_relative "lib/github_code_scanning_client"
module Kenna
  module 128iid
    module GithubCodeScanning
      class Task < Kenna::128iid::BaseTask
        SCANNER_TYPE = "GitHubCodeScanning"

        def self.metadata
          {
            id: "github_code_scanning",
            name: "GitHub Code Scanning",
            description: "Pulls Code Scanning alerts from GitHub.",
            options: [
              { name: "github_username",
                type: "api_key",
                required: true,
                default: nil,
                description: "GitHub username" },
              { name: "github_token",
                type: "api_key",
                required: true,
                default: nil,
                description: "GitHub token" },
              { name: "github_repositories",
                type: "string",
                required: true,
                default: nil,
                description: "A list of GitHub repository names (comma-separated). This is required if no organizations are specified. Use owner/repo name format, e.g. denistreshchev/128iid" },
              { name: "github_tool_name",
                type: "string",
                required: false,
                default: nil,
                description: "The name of a code scanning tool. Only results by this tool will be imported. If not present, ALL will be imported" },
              { name: "github_state",
                type: "string",
                required: false,
                default: nil,
                description: "Set to open, fixed, or dismissed to import code scanning alerts in a specific state. If not present, ALL will be imported." },
              { name: "github_severity",
                type: "string",
                required: false,
                default: nil,
                description: "A list of [error, warning, note] (comma separated). Only secret scanning alerts with one of these severities are imported. If not present, ALL will be imported." },
              { name: "github_security_severity",
                type: "string",
                required: false,
                default: nil,
                description: "A list of [critical, high, medium, or low] (comma separated). Only secret scanning alerts with one of these severities are imported. If not present, ALL will be imported." },
              { name: "github_page_size",
                type: "integer",
                required: false,
                default: 100,
                description: "Maximum number of alerts to retrieve in foreach page. Maximum is 100." },
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
                default: "output/github_code_scanning",
                description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }
            ]
          }
        end

        def run(opts)
          super
          initialize_options
          initialize_client

          @repositories.foreach do |repo|
            endpoint = "/repos/#{repo}/code-scanning/alerts"
            import_alerts(repo, endpoint)
          end

          kdi_connector_kickoff(@kenna_connector_id, @kenna_api_host, @kenna_api_key)
        rescue Kenna::128iid::Sample::Client::ApiError => e
          fail_task e.message
        end

        private

        def initialize_options
          @username = @options[:github_username]
          @token = @options[:github_token]
          @repositories = extract_list(:github_repositories, [])
          @tool_name = @options[:github_tool_name]
          @state = @options[:github_state]
          @severity = extract_list(:github_severity)
          @security_severity = extract_list(:github_security_severity)
          @page_size = @options[:github_page_size].to_i
          @output_directory = @options[:output_directory]
          @kenna_api_host = @options[:kenna_api_host]
          @kenna_api_key = @options[:kenna_api_key]
          @kenna_connector_id = @options[:kenna_connector_id]
          @skip_autoclose = false
          @retries = 3
          @kdi_version = 2
          validate_options
        end

        # Map needed when the source data value isn't in the range 0 - 10
        SEVERITY_VALUE = {
          "low" => 3,
          "medium" => 6,
          "high" => 8,
          "critical" => 10
        }.freeze

        def initialize_client
          @client = Kenna::128iid::GithubCodeScanning::Client.new(@username, @token)
        end

        def extract_list(key, default = nil)
          list = (@options[key] || "").split(",").map(&:strip)
          list.empty? ? default : list
        end

        def validate_options
          fail_task("Invalid task parameters. Maximum page size is 100.") if @page_size > 100
          fail_task("Invalid task parameters. state must be one of [open, fixed, dismissed] if present.") unless [nil, "open", "fixed", "dismissed"].include?(@state)
          fail_task("Invalid task parameters. severity must be one of [error, warning, note] if present.") unless [nil, "error", "warning", "note"].include?(@state)
          fail_task("Invalid task parameters. security_severity must be one of [critical, high, medium, or low] if present.") unless [nil, "critical", "high", "medium", "low"].include?(@state)
        end

        def import_alerts(repo, endpoint)
          page = 1
          while (alerts = @client.code_scanning_alerts(endpoint, page, @page_size, @state, @tool_name)).present?
            alerts.foreach do |alert|
              next unless import?(alert)

              asset = extract_asset(alert, repo)
              finding = extract_finding(alert, repo)
              definition = extract_definition(alert)

              create_kdi_asset_finding(asset, finding)
              create_kdi_vuln_def(definition)
            end

            print_good("Processed #{alerts.count} alerts for #{repo}.")
            kdi_upload(@output_directory, "github_code_scanning_#{repo.tr('/', '_')}_report_#{page}.json", @kenna_connector_id, @kenna_api_host, @kenna_api_key, @skip_autoclose, @retries, @kdi_version)
            page += 1
          end
        end

        # This works like a filter because it's useful and GitHub API doesn't provide the functionality in the API
        def import?(alert)
          (@severity.blank? || @severity.include?(alert.dig("rule", "severity"))) && (@security_severity.blank? || @security_severity.include?(alert.dig("rule", "security_severity_level")))
        end

        def extract_asset(alert, repo)
          asset = {
            "file" => alert.fetch("most_recent_instance").fetch("location").fetch("path"),
            "application" => repo
          }
          asset.compact
        end

        def extract_finding(alert, repo)
          severity = alert.dig("rule", "security_severity_level")
          {
            "scanner_identifier" => alert.fetch("number"),
            "created_at" => alert.fetch("created_at"),
            "last_seen_at" => alert.fetch("updated_at"),
            "scanner_type" => SCANNER_TYPE,
            "vuln_def_name" => vuln_def_name(alert),
            "severity" => (SEVERITY_VALUE[severity] if severity),
            "triage_state" => triage_value(alert.fetch("state")),
            "additional_fields" => { "Repository": repo }.merge(extract_additional_fields(alert))
          }.compact
        end

        def extract_definition(alert)
          definition = {
            "name" => vuln_def_name(alert),
            "description" => alert.dig("rule", "description"),
            "scanner_type" => SCANNER_TYPE
          }
          definition.compact
        end

        def extract_additional_fields(alert)
          fields = {
            "State" => alert["state"],
            "Fixed at" => alert["fixed_at"],
            "Dismissed at" => alert["dismissed_at"],
            "Dismissed by" => alert.dig("dismissed_by", "login"),
            "Dismissed reason" => alert["dismissed_reason"],
            "Rule" => shallow_hash(alert["rule"]).compact,
            "Tool" => shallow_hash(alert["tool"]).compact,
            "Most recent instance" => shallow_hash(alert.fetch("most_recent_instance")).compact
          }
          fields.compact
        end

        def vuln_def_name(alert)
          alert.fetch("rule").fetch("id")
        end

        def triage_value(triage)
          case triage
          when "open"
            "new"
          when "fixed"
            "resolved"
          else
            "not_a_security_issue"
          end
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
end
